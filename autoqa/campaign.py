"""Campaign orchestration: the full fuzz -> observe -> analyze -> report loop."""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import httpx

from autoqa.analysis.cluster import Cluster, cluster_findings
from autoqa.analysis.minimizer import is_minimizable, minimize, same_failure
from autoqa.analysis.oracles import Finding, evaluate
from autoqa.analysis.traces import StackTrace, extract_traces
from autoqa.fuzz.engine import TestCase, build_cases
from autoqa.runner.executor import Executor, Result
from autoqa.runner.process import TargetProcess
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
                    + "\n".join(l.text for l in process.all_lines()[-25:])
                )
            self._log("target is ready")

        try:
            cases = list(
                build_cases(operations, cfg.cases_per_operation, cfg.seed)
            )
            self._log(f"generated {len(cases)} test cases")

            executor = Executor(
                cfg.base_url,
                concurrency=cfg.concurrency,
                timeout=cfg.timeout,
                auth_header=cfg.auth_header,
                rate_limit_per_sec=cfg.rate_limit_per_sec,
            )
            results = await executor.run(cases)
            self._log(f"executed {len(results)} requests")

            traces: list[StackTrace] = []
            if process is not None:
                traces = extract_traces(process.lines_since(started))
                if traces:
                    self._log(f"extracted {len(traces)} stack traces from target logs")

            findings = evaluate(results)
            clusters = cluster_findings(findings, traces)
            self._log(f"{len(findings)} findings in {len(clusters)} distinct clusters")

            minimized: dict[str, TestCase] = {}
            if cfg.minimize_findings and clusters:
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
            )
        finally:
            if process is not None:
                process.stop()

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
