"""Campaign orchestration: the full fuzz -> observe -> analyze -> report loop."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from autoqa.analysis.cluster import Cluster, cluster_findings
from autoqa.analysis.minimizer import is_minimizable, minimize, same_failure
from autoqa.analysis.oracles import Finding, evaluate
from autoqa.analysis.sequence_oracles import evaluate_sequence
from autoqa.analysis.traces import StackTrace, extract_traces
from autoqa.fuzz.engine import TestCase, build_cases
from autoqa.fuzz.sequences import build_sequences, discover_resources
from autoqa.fuzz.sweep import SECURITY_PAYLOADS, build_sweep_cases
from autoqa.runner.executor import Executor, Result
from autoqa.runner.process import TargetProcess
from autoqa.runner.sequence_runner import SequenceRun, SequenceRunner
from autoqa.spec.parser import OpenAPISpec, Operation


@dataclass
class CampaignConfig:
    spec_path: str
    base_url: str
    cases_per_operation: int = 25
    seed: int = 1337
    concurrency: int = 8
    timeout: float = 10.0
    launch_command: str | None = None
    launch_cwd: str | None = None
    health_path: str = "/"
    auth_header: tuple[str, str] | None = None
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    minimize_findings: bool = True
    rate_limit_per_sec: float | None = None
    # Send every security payload to every string parameter exactly once, on
    # top of the random cases. Makes injection coverage a guarantee rather than
    # a function of --cases; see autoqa/fuzz/sweep.py.
    security_sweep: bool = True
    # Chain requests so later steps act on state earlier ones created. Finds
    # use-after-delete and non-idempotent transitions that independent requests
    # cannot reach; see autoqa/fuzz/sequences.py.
    stateful_sequences: bool = True


@dataclass
class CampaignReport:
    config: CampaignConfig
    operations: list[Operation]
    results: list[Result]
    findings: list[Finding]
    clusters: list[Cluster]
    traces: list[StackTrace]
    started_at: float
    duration_s: float
    target_died: bool = False
    minimized: dict[str, TestCase] = field(default_factory=dict)
    sequence_runs: list[SequenceRun] = field(default_factory=list)

    @property
    def total_requests(self) -> int:
        return len(self.results)

    @property
    def status_histogram(self) -> dict[str, int]:
        histogram: dict[str, int] = {}
        for result in self.results:
            key = str(result.status) if result.status else (result.transport_error or "error")
            histogram[key] = histogram.get(key, 0) + 1
        return dict(sorted(histogram.items()))


ProgressHook = Callable[[str], None]

# Replays per (operation, error-class) group during transport confirmation.
# More than one guards against a flaky single sample; many more just re-proves
# the same fact at the cost of a full --timeout each.
MAX_CONFIRMATIONS_PER_GROUP = 2


class Campaign:
    def __init__(self, config: CampaignConfig, on_progress: ProgressHook | None = None) -> None:
        self.config = config
        self._log = on_progress or (lambda _msg: None)

    def run(self) -> CampaignReport:
        return asyncio.run(self.run_async())

    async def run_async(self) -> CampaignReport:
        cfg = self.config
        started = time.time()

        spec = OpenAPISpec.from_file(cfg.spec_path)
        operations = self._filter(spec.operations())
        if not operations:
            raise ValueError("no operations matched the include/exclude filters")
        self._log(f"loaded {len(operations)} operations from {cfg.spec_path}")

        process: TargetProcess | None = None
        if cfg.launch_command:
            process = TargetProcess(cfg.launch_command, cwd=cfg.launch_cwd)
            process.start()
            health = cfg.base_url.rstrip("/") + cfg.health_path
            self._log(f"launched target, waiting for {health}")
            if not process.wait_until_ready(health, timeout=45.0):
                process.stop()
                raise RuntimeError(
                    f"target did not become ready at {health}. "
                    f"Last output:\n"
                    + "\n".join(line.text for line in process.all_lines()[-25:])
                )
            self._log("target is ready")

        try:
            cases = list(
                build_cases(operations, cfg.cases_per_operation, cfg.seed)
            )
            self._log(f"generated {len(cases)} test cases")

            if cfg.security_sweep:
                sweep = list(build_sweep_cases(operations, cfg.seed))
                if sweep:
                    self._log(
                        f"+{len(sweep)} deterministic security probes "
                        f"({len(SECURITY_PAYLOADS)} payloads x "
                        f"{len(sweep) // len(SECURITY_PAYLOADS)} injectable targets)"
                    )
                    cases += sweep

            executor = Executor(
                cfg.base_url,
                concurrency=cfg.concurrency,
                timeout=cfg.timeout,
                auth_header=cfg.auth_header,
                rate_limit_per_sec=cfg.rate_limit_per_sec,
            )
            results = await executor.run(cases)
            self._log(f"executed {len(results)} requests")

            results = await self._confirm_transport_failures(results)

            traces: list[StackTrace] = []
            if process is not None:
                traces = extract_traces(process.lines_since(started))
                if traces:
                    self._log(f"extracted {len(traces)} stack traces from target logs")

            findings = evaluate(results)

            sequence_runs: list[SequenceRun] = []
            if cfg.stateful_sequences:
                sequence_runs = await self._run_sequences(operations, executor)
                for run in sequence_runs:
                    findings.extend(evaluate_sequence(run))

            clusters = cluster_findings(findings, traces)
            self._log(f"{len(findings)} findings in {len(clusters)} distinct clusters")

            minimized: dict[str, TestCase] = {}
            if cfg.minimize_findings and clusters:
                # Minimization issues hundreds of single-case runs; holding one
                # client open across them turns per-call connection setup from
                # the dominant cost into a one-off.
                async with executor:
                    minimized = await self._minimize_all(clusters, executor)

            target_died = process is not None and not process.is_alive
            if target_died:
                self._log("WARNING: target process is no longer running")

            return CampaignReport(
                config=cfg,
                operations=operations,
                results=results,
                findings=findings,
                clusters=clusters,
                traces=traces,
                started_at=started,
                duration_s=time.time() - started,
                target_died=target_died,
                minimized=minimized,
                sequence_runs=sequence_runs,
            )
        finally:
            if process is not None:
                process.stop()

    async def _run_sequences(
        self, operations: list[Operation], executor: Executor
    ) -> list[SequenceRun]:
        """Discover resources, then run each abuse pattern against them."""
        resources = discover_resources(operations)
        if not resources:
            self._log("no create+act resource pairs found; skipping sequences")
            return []

        planned = [seq for r in resources for seq in build_sequences(r)]
        if not planned:
            return []

        self._log(
            f"running {len(planned)} stateful sequences across "
            f"{len(resources)} resource(s)"
        )

        # Sequences must run in order on shared state, so one client is held
        # open across the whole set rather than rebuilt per step.
        runner = SequenceRunner(executor, seed=self.config.seed)
        runs: list[SequenceRun] = []
        async with executor:
            for index, sequence in enumerate(planned):
                runs.append(await runner.run(sequence, index))

        aborted = sum(1 for r in runs if not r.completed)
        if aborted:
            self._log(
                f"{aborted} sequence(s) could not complete "
                f"(setup step failed, so later steps had no resource to act on)"
            )
        return runs

    async def _confirm_transport_failures(self, results: list[Result]) -> list[Result]:
        """Re-run each transport failure alone, and keep only those that recur.

        A dropped connection is not attributable to one request. HTTP keep-alive
        means several requests share a connection, so one payload that makes the
        server hang up takes its innocent siblings down with it — and each of
        those siblings then looks like its own crash. Measured on the demo API,
        concurrency 6 produced 14 `ReadError`s where concurrency 1 produced 5;
        the other 9 were collateral, and reporting them means shipping
        reproducers that provably do not reproduce.

        Replaying serially on a fresh connection is the only way to tell the two
        apart. It costs one request per suspected failure, which is cheap
        relative to the campaign and much cheaper than a false finding.
        """
        # Track positions, not object identity, so the merge back is unambiguous.
        # `InvalidURL` is excluded: httpx refused to send those itself, making
        # them per-request facts about the input rather than connection noise.
        replayable = [
            index
            for index, r in enumerate(results)
            if r.transport_error and not r.transport_error.startswith("InvalidURL")
        ]
        if not replayable:
            return results

        # Confirming every suspect individually is enormous waste when they are
        # the same defect. One run produced 120 timeouts that clustered into 5
        # issues: 120 replays, each burning the full --timeout, to establish 5
        # facts. Confirmation happens before clustering and so cannot see that,
        # but suspects can be grouped by the same key clustering will use.
        #
        # Sampling is sound in one direction only. If a sample still fails, the
        # input class genuinely fails and its siblings inherit the verdict. If
        # every sample comes back clean the group was collateral, and *all* its
        # members are replaced by their replays rather than kept on the strength
        # of an unverified original.
        groups: dict[tuple[str, str], list[int]] = {}
        for index in replayable:
            result = results[index]
            key = (
                result.case.operation.key,
                (result.transport_error or "").split(":")[0],
            )
            groups.setdefault(key, []).append(index)

        sampled = [i for indices in groups.values() for i in indices[:MAX_CONFIRMATIONS_PER_GROUP]]
        skipped = len(replayable) - len(sampled)
        self._log(
            f"confirming {len(sampled)} transport failures on fresh connections"
            + (
                f" ({skipped} inherit their group's verdict across "
                f"{len(groups)} operation/error groups)"
                if skipped
                else ""
            )
        )
        replayable = sampled

        async def verify(index: int) -> tuple[int, Result | None]:
            # A fresh single-slot Executor per replay. Isolation is the point —
            # these must not share a connection with each other or with the main
            # run — but they are independent, so they can still run in parallel.
            verifier = Executor(
                self.config.base_url,
                concurrency=1,
                timeout=self.config.timeout,
                auth_header=self.config.auth_header,
                rate_limit_per_sec=self.config.rate_limit_per_sec,
            )
            replayed = await verifier.run([results[index].case])
            return index, (replayed[0] if replayed else None)

        # Bound the fan-out: too many simultaneous replays would recreate the
        # very connection pressure this pass exists to rule out.
        semaphore = asyncio.Semaphore(min(4, self.config.concurrency))

        async def guarded(index: int) -> tuple[int, Result | None]:
            async with semaphore:
                return await verify(index)

        out = list(results)
        verdicts: dict[int, bool] = {}
        for index, replayed in await asyncio.gather(
            *(guarded(i) for i in replayable)
        ):
            if replayed is None:
                continue
            # Take the replay either way: if it still fails at the transport
            # level the finding is real, and if it came back with a status that
            # status is the truth (a genuine 500 can hide behind collateral
            # damage). Its timing is also what a reader will actually see.
            out[index] = replayed
            verdicts[index] = bool(replayed.transport_error)

        dropped = 0
        for indices in groups.values():
            tested = [i for i in indices if i in verdicts]
            if not tested:
                continue
            confirmed = any(verdicts[i] for i in tested)
            for index in indices:
                if index in verdicts:
                    dropped += 0 if verdicts[index] else 1
                    continue
                # Unsampled sibling. A confirmed group keeps its members as-is;
                # an unconfirmed one must not leave them reported on the
                # strength of an original we now believe was collateral.
                if not confirmed:
                    out[index] = out[tested[0]]
                    dropped += 1

        if dropped:
            self._log(
                f"dropped {dropped} unconfirmed transport failure(s) "
                f"(collateral from connection sharing, not target defects)"
            )

        return out

    async def _minimize_all(
        self, clusters: list[Cluster], executor: Executor
    ) -> dict[str, TestCase]:
        """Shrink each cluster's exemplar to a minimal reproducer."""
        # Only worth doing for clusters we can actually re-trigger and verify.
        candidates = [
            c
            for c in clusters
            if not c.exemplar.result.case.is_baseline
            and is_minimizable(c.exemplar.result)
        ][:15]
        skipped = len(clusters) - len(candidates)
        if not candidates:
            if skipped:
                self._log(f"skipped minimizing {skipped} cluster(s); reporting full requests")
            return {}
        self._log(
            f"minimizing {len(candidates)} reproducers"
            + (f" ({skipped} not safely minimizable)" if skipped else "")
        )

        minimized: dict[str, TestCase] = {}
        for cluster in candidates:
            original = cluster.exemplar.result
            matches = same_failure(original)

            async def still_fails(case: TestCase, _matches=matches) -> bool:
                replayed = await executor.run([case])
                return bool(replayed) and _matches(replayed[0])

            # Confirm it reproduces at all before spending requests shrinking it;
            # a flaky one-off would otherwise minimize down to nonsense.
            if not await still_fails(original.case):
                continue
            minimized[cluster.signature] = await minimize(original.case, still_fails)
        return minimized

    def _filter(self, operations: list[Operation]) -> list[Operation]:
        cfg = self.config
        out = operations
        if cfg.include:
            out = [
                op for op in out
                if any(pattern.lower() in op.key.lower() for pattern in cfg.include)
            ]
        if cfg.exclude:
            out = [
                op for op in out
                if not any(pattern.lower() in op.key.lower() for pattern in cfg.exclude)
            ]
        return out
