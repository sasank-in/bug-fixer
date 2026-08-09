"""Oracles: rules that decide whether a response indicates a real bug.

A fuzzer without good oracles just produces noise. The hard part is not
generating hostile input, it is deciding that a given 400 is correct behaviour
while a given 500 is a defect. Each oracle here returns zero or more Findings.
"""

from __future__ import annotations

import re
import statistics
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import Enum

from autoqa.runner.executor import Result


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }[self]


@dataclass
class Finding:
    """One suspected defect, tied to the exact request that triggered it."""

    kind: str
    severity: Severity
    title: str
    detail: str
    result: Result
    evidence: list[str] = field(default_factory=list)

    @property
    def operation_key(self) -> str:
        return self.result.case.operation.key


Oracle = Callable[[Result], list[Finding]]


# Text that should never appear in a response body: it means an internal error
# leaked to the client rather than being handled.
_LEAK_PATTERNS: tuple[tuple[str, re.Pattern[str], Severity], ...] = (
    ("python_traceback", re.compile(r"Traceback \(most recent call last\)"), Severity.HIGH),
    ("stack_trace_js", re.compile(r"\bat [\w.$]+ \([^)]*:\d+:\d+\)"), Severity.HIGH),
    ("java_trace", re.compile(r"\bat (?:[a-z]\w*\.)+[A-Z]\w*\.[\w$]+\("), Severity.HIGH),
    ("sql_error", re.compile(
        r"(?i)\b(syntax error at or near|SQLSTATE|sqlite3\.\w+Error|"
        r"ORA-\d{5}|You have an error in your SQL syntax|psycopg2\.\w+)"
    ), Severity.CRITICAL),
    ("filesystem_path", re.compile(r"(?i)(?:[A-Z]:\\Users\\|/home/\w+/|/var/www/|/etc/passwd)"), Severity.MEDIUM),
    ("secret_like", re.compile(
        r"(?i)\b(?:api[_-]?key|secret[_-]?key|password|access[_-]?token)\"?\s*[:=]\s*\"?[A-Za-z0-9_\-]{12,}"
    ), Severity.CRITICAL),
    ("debug_mode", re.compile(r"(?i)(werkzeug debugger|DEBUG = True|django\.core\.exceptions)"), Severity.MEDIUM),
)

# Reflected payloads that indicate injection reached a sink.
_INJECTION_MARKERS: tuple[tuple[str, str, Severity], ...] = (
    ("template_injection", "49", Severity.CRITICAL),  # {{7*7}} evaluated
    ("path_traversal", "root:x:0:0", Severity.CRITICAL),
    ("path_traversal_win", "[fonts]", Severity.CRITICAL),
)


def oracle_server_error(result: Result) -> list[Finding]:
    """5xx on a mutated request means unhandled input reached the server."""
    if result.status is None or result.status < 500:
        return []
    # 501/505 are honest "not supported" answers, not crashes.
    if result.status in (501, 505):
        return []

    if result.case.is_baseline:
        # Schema-valid input failing is a different, usually more urgent bug
        # than hostile input failing — and it often means the endpoint needs
        # setup (auth, seeded data) rather than that it is broken. Keep it a
        # separate kind so it clusters on its own instead of inflating the
        # mutation findings around it.
        return [
            Finding(
                kind="baseline_failure",
                severity=Severity.CRITICAL,
                title=f"Valid request fails with {result.status} on {result.case.operation.key}",
                detail=(
                    f"A schema-conforming request returned {result.status}. Either the "
                    f"endpoint is broken for legitimate input, or it needs preconditions "
                    f"(auth, existing records) that this run did not set up — in which "
                    f"case other findings for this operation may be unreliable."
                ),
                result=result,
                evidence=[result.body_text[:500]] if result.body_text else [],
            )
        ]

    return [
        Finding(
            kind="server_error",
            severity=Severity.HIGH if result.status == 500 else Severity.MEDIUM,
            title=f"HTTP {result.status} on {result.case.operation.key}",
            detail=(
                f"Request returned {result.status}. Input should be rejected with a "
                f"4xx or handled, not raise an unhandled server error."
            ),
            result=result,
            evidence=[result.body_text[:500]] if result.body_text else [],
        )
    ]


def oracle_transport_failure(result: Result) -> list[Finding]:
    """Connection resets and timeouts mean the server died or hung."""
    if not result.transport_error:
        return []
    is_timeout = result.transport_error == "timeout"
    return [
        Finding(
            kind="hang" if is_timeout else "connection_failure",
            severity=Severity.HIGH if is_timeout else Severity.CRITICAL,
            title=(
                f"{'Timeout' if is_timeout else 'Connection failure'} on "
                f"{result.case.operation.key}"
            ),
            detail=(
                f"Transport-level failure: {result.transport_error}. This usually means "
                f"the input crashed the worker, exhausted a resource, or hit an "
                f"unbounded operation."
            ),
            result=result,
            evidence=[f"elapsed {result.elapsed_ms:.0f}ms"],
        )
    ]


def oracle_information_leak(result: Result) -> list[Finding]:
    """Internal detail in a response body is a bug regardless of status code."""
    if not result.body_text:
        return []
    findings: list[Finding] = []
    for kind, pattern, severity in _LEAK_PATTERNS:
        match = pattern.search(result.body_text)
        if not match:
            continue
        snippet = result.body_text[
            max(0, match.start() - 80) : match.end() + 120
        ]
        findings.append(
            Finding(
                kind=f"leak_{kind}",
                severity=severity,
                title=f"Internal detail leaked ({kind}) on {result.case.operation.key}",
                detail=(
                    f"Response body exposes internal implementation detail matching "
                    f"'{kind}'. This aids attackers and indicates missing error handling."
                ),
                result=result,
                evidence=[snippet],
            )
        )
    return findings


def oracle_injection_reflection(result: Result) -> list[Finding]:
    """A payload that got *evaluated* rather than echoed is a confirmed injection."""
    if not result.body_text or result.case.is_baseline:
        return []
    sent = " ".join(str(m.value) for m in result.case.mutations)
    findings: list[Finding] = []
    for kind, marker, severity in _INJECTION_MARKERS:
        # Only meaningful if we actually sent the corresponding payload and the
        # marker is in the response but was NOT part of what we sent.
        if marker in result.body_text and marker not in sent:
            trigger = {
                "template_injection": "{{7*7}}",
                "path_traversal": "etc/passwd",
                "path_traversal_win": "win.ini",
            }[kind]
            if trigger not in sent:
                continue
            findings.append(
                Finding(
                    kind=kind,
                    severity=severity,
                    title=f"Possible {kind.replace('_', ' ')} on {result.case.operation.key}",
                    detail=(
                        f"Sent payload containing '{trigger}' and the response contains "
                        f"'{marker}', suggesting the payload was evaluated or resolved "
                        f"server-side rather than treated as data."
                    ),
                    result=result,
                    evidence=[result.body_text[:400]],
                )
            )
    return findings


def oracle_undocumented_status(result: Result) -> list[Finding]:
    """A 2xx on deliberately invalid input means validation is missing."""
    if result.status is None or result.case.is_baseline:
        return []
    if not (200 <= result.status < 300):
        return []
    structural = {"drop_required", "type_confusion", "unknown_field"}
    tags = {m.tag for m in result.case.mutations}
    if not (tags & structural):
        return []
    return [
        Finding(
            kind="missing_validation",
            severity=Severity.MEDIUM,
            title=f"Invalid input accepted with {result.status} on {result.case.operation.key}",
            detail=(
                f"Applied {', '.join(sorted(tags & structural))} yet the endpoint "
                f"returned {result.status}. Schema-violating input should be rejected "
                f"with 400/422."
            ),
            result=result,
            evidence=[m.describe() for m in result.case.mutations],
        )
    ]


DEFAULT_ORACLES: tuple[Oracle, ...] = (
    oracle_server_error,
    oracle_transport_failure,
    oracle_information_leak,
    oracle_injection_reflection,
    oracle_undocumented_status,
)


def evaluate(results: Iterable[Result], oracles: Iterable[Oracle] = DEFAULT_ORACLES) -> list[Finding]:
    findings: list[Finding] = []
    results = list(results)
    for result in results:
        for oracle in oracles:
            findings.extend(oracle(result))
    findings.extend(_oracle_latency_outliers(results))
    return findings


def _oracle_latency_outliers(results: list[Result]) -> list[Finding]:
    """Flag responses far slower than that operation's own baseline.

    Cross-operation comparison would be meaningless, so this groups by
    operation and needs a real sample before calling anything an outlier.
    """
    by_op: dict[str, list[Result]] = {}
    for result in results:
        if result.status is not None:
            by_op.setdefault(result.case.operation.key, []).append(result)

    findings: list[Finding] = []
    for key, group in by_op.items():
        timings = [r.elapsed_ms for r in group]
        if len(timings) < 8:
            continue
        median = statistics.median(timings)
        if median <= 0:
            continue
        for result in group:
            # 10x the median and at least a second: avoids flagging 2ms vs 20ms.
            if result.elapsed_ms > median * 10 and result.elapsed_ms > 1000:
                findings.append(
                    Finding(
                        kind="latency_outlier",
                        severity=Severity.MEDIUM,
                        title=f"Slow response ({result.elapsed_ms:.0f}ms) on {key}",
                        detail=(
                            f"Took {result.elapsed_ms:.0f}ms against a median of "
                            f"{median:.0f}ms for this operation — a potential algorithmic "
                            f"complexity or resource-exhaustion vector."
                        ),
                        result=result,
                        evidence=[f"median={median:.0f}ms", f"n={len(timings)}"],
                    )
                )
    return findings
