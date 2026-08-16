"""Execute stateful sequences against a live target.

Unlike the main executor, this cannot batch: each step's request depends on the
previous step's *response*, so the chain must run in order on one connection.
That is also what makes it slow, so sequences are run once each rather than
sampled repeatedly.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass, field

from autoqa.fuzz.sequences import Sequence, extract_id, realise_step
from autoqa.runner.executor import Executor, Result


@dataclass
class StepOutcome:
    """One executed step, and what it yielded for later steps."""

    index: int
    result: Result
    note: str
    expect_failure: bool
    extracted_id: object = None


@dataclass
class SequenceRun:
    """A sequence that was executed, with every step's outcome."""

    sequence: Sequence
    outcomes: list[StepOutcome] = field(default_factory=list)
    # Set when the chain could not continue — e.g. the create step failed, so
    # there was no id to act on. Not a finding in itself.
    aborted_at: int | None = None
    abort_reason: str = ""

    @property
    def completed(self) -> bool:
        return self.aborted_at is None


class SequenceRunner:
    """Runs sequences step by step, threading ids between them."""

    def __init__(self, executor: Executor, seed: int = 0) -> None:
        self.executor = executor
        self.seed = seed

    async def run(self, sequence: Sequence, index: int = 0) -> SequenceRun:
        run = SequenceRun(sequence=sequence)
        rng = random.Random(self.seed + index * 7919)
        ids: dict[int, object] = {}

        for position, step in enumerate(sequence.steps):
            resource_id = (
                ids.get(step.id_from_step) if step.id_from_step is not None else None
            )
            if step.id_from_step is not None and resource_id is None:
                # The step this one depends on produced no usable id, so acting
                # "on the resource" would really be acting on a generated value
                # and any failure would be meaningless.
                run.aborted_at = position
                run.abort_reason = (
                    f"step {step.id_from_step} returned no usable resource id"
                )
                return run

            case = realise_step(step, resource_id, rng)
            results = await self.executor.run([case])
            if not results:
                run.aborted_at = position
                run.abort_reason = "request produced no result"
                return run

            result = results[0]
            extracted = self._extract(result)
            ids[position] = extracted
            run.outcomes.append(
                StepOutcome(
                    index=position,
                    result=result,
                    note=step.note,
                    expect_failure=step.expect_failure,
                    extracted_id=extracted,
                )
            )

            # A transport-level failure ends the chain: subsequent steps would
            # be acting on unknown state.
            if result.transport_error:
                run.aborted_at = position
                run.abort_reason = f"transport failure: {result.transport_error}"
                return run

        return run

    def _extract(self, result: Result) -> object:
        if result.status is None or not (200 <= result.status < 300):
            return None
        if not result.body_text:
            return None
        try:
            body = json.loads(result.body_text)
        except (ValueError, TypeError):
            return None
        # A top-level scalar response *is* the id — there is nothing else it
        # could be. Inside an object it would be ambiguous, which is why
        # extract_id only recurses into containers.
        if isinstance(body, (int, str)) and not isinstance(body, bool):
            return body if str(body).strip() else None
        return extract_id(body)
