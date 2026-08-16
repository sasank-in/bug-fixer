"""Oracles for stateful sequences.

Single-request oracles ask "is this response wrong?". These ask "is this
response wrong *given what happened before it?*" — a 500 on step three is only
interesting because steps one and two succeeded and put the server in a state
it then mishandled.

The same discipline applies as everywhere else: a correct rejection is not a
bug. Deleting twice and getting 404 is right; getting 500 is not.
"""

from __future__ import annotations

from autoqa.analysis.oracles import Finding, Severity
from autoqa.runner.sequence_runner import SequenceRun


def evaluate_sequence(run: SequenceRun) -> list[Finding]:
    """Findings implied by how a whole sequence behaved."""
    findings: list[Finding] = []
    for check in (_server_error_mid_sequence, _accepted_after_delete, _stale_read):
        findings.extend(check(run))
    return findings


def _context(run: SequenceRun, upto: int) -> str:
    """Human-readable prefix describing how the server got into this state."""
    parts = []
    for outcome in run.outcomes[:upto]:
        op = outcome.result.case.operation
        parts.append(f"{op.method} {outcome.result.case.path} -> {outcome.result.status}")
    return " then ".join(parts)


def _server_error_mid_sequence(run: SequenceRun) -> list[Finding]:
    """A 5xx that only appears once earlier steps have run.

    This is the core sequence finding: the endpoint handles a fresh request
    fine, so single-request fuzzing reports it clean, but it crashes on state
    a previous step created.
    """
    findings: list[Finding] = []
    for outcome in run.outcomes:
        status = outcome.result.status
        if status is None or status < 500 or status in (501, 505):
            continue
        # A failure on the very first step is not a sequence bug — there was no
        # prior state — and the ordinary oracles already cover it.
        if outcome.index == 0:
            continue

        findings.append(
            Finding(
                kind="stateful_crash",
                severity=Severity.CRITICAL,
                title=(
                    f"HTTP {status} on {outcome.result.case.operation.key} "
                    f"after {run.sequence.name}"
                ),
                detail=(
                    f"{run.sequence.hypothesis}. Reached by: "
                    f"{_context(run, outcome.index)}. Step {outcome.index} "
                    f"({outcome.note or 'no note'}) then returned {status}. "
                    f"The endpoint handles this request in isolation, so only "
                    f"the preceding sequence exposes the defect."
                ),
                result=outcome.result,
                evidence=[
                    f"sequence: {run.sequence.label}",
                    outcome.result.body_text[:300],
                ],
            )
        )
    return findings


def _accepted_after_delete(run: SequenceRun) -> list[Finding]:
    """A step marked `expect_failure` that succeeded anyway.

    Reading, updating, or acting on a deleted resource must not return 2xx.
    When it does, the delete did not really delete.
    """
    findings: list[Finding] = []
    for outcome in run.outcomes:
        if not outcome.expect_failure:
            continue
        status = outcome.result.status
        if status is None or not (200 <= status < 300):
            continue

        findings.append(
            Finding(
                kind="stale_state_accepted",
                severity=Severity.HIGH,
                title=(
                    f"{outcome.result.case.operation.key} succeeded on a deleted "
                    f"resource ({run.sequence.name})"
                ),
                detail=(
                    f"{run.sequence.hypothesis}. Reached by: "
                    f"{_context(run, outcome.index)}. The request then returned "
                    f"{status} instead of 404, so the resource is still "
                    f"reachable after deletion."
                ),
                result=outcome.result,
                evidence=[
                    f"sequence: {run.sequence.label}",
                    outcome.result.body_text[:300],
                ],
            )
        )
    return findings


def _stale_read(run: SequenceRun) -> list[Finding]:
    """A read that does not reflect the write immediately preceding it."""
    if run.sequence.name != "update_then_read" or len(run.outcomes) < 3:
        return []

    write, read = run.outcomes[1], run.outcomes[2]
    if write.result.status is None or not (200 <= write.result.status < 300):
        return []
    if read.result.status is None or not (200 <= read.result.status < 300):
        return []

    import json

    try:
        written = json.loads(write.result.body_text)
        got = json.loads(read.result.body_text)
    except (ValueError, TypeError):
        return []
    if not isinstance(written, dict) or not isinstance(got, dict):
        return []

    # Only compare fields the write actually echoed back; anything else is the
    # server's own bookkeeping and may legitimately differ.
    mismatched = [
        key
        for key, value in written.items()
        # Skip counters and timestamps the server owns and may bump on read.
        if key not in ("version", "updated_at", "modified", "etag")
        and key in got
        and got[key] != value
    ]
    if not mismatched:
        return []

    return [
        Finding(
            kind="stale_read",
            severity=Severity.HIGH,
            title=(
                f"Read after write returned stale data on "
                f"{read.result.case.operation.key}"
            ),
            detail=(
                f"An update returned one value and the immediately following "
                f"read returned another for: {', '.join(sorted(mismatched))}. "
                f"This points at a caching or replication lag that clients "
                f"cannot see or work around."
            ),
            result=read.result,
            evidence=[
                f"sequence: {run.sequence.label}",
                f"wrote: {json.dumps({k: written.get(k) for k in mismatched})[:200]}",
                f"read:  {json.dumps({k: got.get(k) for k in mismatched})[:200]}",
            ],
        )
    ]
