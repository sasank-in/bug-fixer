"""Group findings into distinct issues.

A fuzzer will hit the same bug hundreds of times. Reporting 400 findings when
there are 6 real defects makes the output useless, so clustering is what turns
raw output into something a human can act on.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from autoqa.analysis.normalize import normalize
from autoqa.analysis.oracles import Finding, Severity
from autoqa.analysis.traces import StackTrace


@dataclass
class Cluster:
    """A set of findings believed to share one root cause."""

    signature: str
    kind: str
    severity: Severity
    findings: list[Finding] = field(default_factory=list)
    trace: StackTrace | None = None

    @property
    def count(self) -> int:
        return len(self.findings)

    @property
    def operations(self) -> list[str]:
        return sorted({f.operation_key for f in self.findings})

    @property
    def mutation_tags(self) -> list[str]:
        """Mutations that triggered *the reported reproducer*, not the cluster.

        Aggregating tags across every member listed mutations belonging to other
        requests, so a report could claim `deep_nesting` for a reproducer whose
        body is `{}`. The exemplar is what the reader will run, so it is the only
        thing the tags may describe. `all_mutation_tags` keeps the wider view.
        """
        return sorted({m.tag for m in self.exemplar.result.case.mutations})

    @property
    def all_mutation_tags(self) -> list[str]:
        """Every mutation that reached this cluster, across all members."""
        return sorted({m.tag for f in self.findings for m in f.result.case.mutations})

    @property
    def exemplar(self) -> Finding:
        """The representative finding — the one whose request the report prints.

        Ordering, most important first:

        1. Worst severity, so the exemplar matches the title and detail.
        2. Fewest mutations, so blame is unambiguous.
        3. Smallest payload, purely as a readability tiebreak.

        Size used to rank above mutation count, which selected whichever member
        happened to carry the tiniest body — frequently *not* a request that
        triggered the failure at all. Replaying the report then produced a
        different status than it claimed. Fidelity outranks brevity: a long
        reproducer that works beats a short one that does not.
        """
        return min(
            self.findings,
            key=lambda f: (
                f.severity.rank,
                len(f.result.case.mutations),
                len(repr(f.result.case.body or "")),
            ),
        )

    @property
    def title(self) -> str:
        return self.exemplar.title

    @property
    def detail(self) -> str:
        return self.exemplar.detail


# Re-exported so existing callers can keep importing it from here.
__all__ = ["Cluster", "cluster_findings", "normalize"]


def cluster_findings(
    findings: list[Finding], traces: list[StackTrace] | None = None
) -> list[Cluster]:
    """Group findings by root cause, preferring stack-trace identity when available."""
    traces = traces or []
    trace_by_norm: dict[str, StackTrace] = {}
    for trace in traces:
        trace_by_norm.setdefault(normalize(trace.message)[:80], trace)

    buckets: dict[str, Cluster] = {}
    for finding in findings:
        trace = _match_trace(finding, traces, trace_by_norm)
        signature = _signature(finding, trace)
        cluster = buckets.get(signature)
        if cluster is None:
            buckets[signature] = Cluster(
                signature=signature,
                kind=finding.kind,
                severity=finding.severity,
                findings=[finding],
                trace=trace,
            )
        else:
            cluster.findings.append(finding)
            # A cluster is as severe as its worst member; title and detail
            # follow automatically because they derive from the exemplar.
            if finding.severity.rank < cluster.severity.rank:
                cluster.severity = finding.severity
            if cluster.trace is None and trace is not None:
                cluster.trace = trace

    ordered = sorted(
        buckets.values(), key=lambda c: (c.severity.rank, -c.count, c.signature)
    )
    return ordered


def _match_trace(
    finding: Finding, traces: list[StackTrace], by_norm: dict[str, StackTrace]
) -> StackTrace | None:
    """Find the server-side trace that this finding's request produced.

    Three strategies, most to least reliable. Body matching only works when the
    app leaks the error text to the client; most correctly-configured apps
    return a bare "Internal Server Error", so time correlation carries the load.
    """
    result = finding.result
    body = result.body_text

    # A timeout or dropped connection means this request produced no response,
    # and under concurrency its window overlaps other requests that did fail.
    # Adopting one of their traces would blame the wrong operation entirely, so
    # these findings stay unattributed rather than confidently wrong.
    if result.transport_error:
        return None

    # 1. The response body quotes the exception message verbatim.
    if body:
        normalized_body = normalize(body)
        for key, trace in by_norm.items():
            if key and len(key) > 12 and key in normalized_body:
                return trace

    # 2. A trace logged while this exact request was in flight.
    if result.sent_at and result.received_at:
        window = [
            t
            for t in traces
            # Small grace period: the trace is flushed just after the response.
            if t.timestamp and result.sent_at <= t.timestamp <= result.received_at + 0.25
        ]
        # A trace whose culprit frame names some *other* endpoint's handler
        # belongs to a concurrent request, no matter how well the timing lines
        # up. Discard those before considering anything else.
        window = [t for t in window if not _names_other_operation(t, result)]

        if len(window) == 1:
            return window[0]
        if window:
            # Under concurrency several requests overlap one window, so timing
            # alone is ambiguous. Prefer a trace whose culprit frame names the
            # handler this request actually hit — that disambiguates by identity
            # rather than by guessing on timing.
            named = [t for t in window if _names_operation(t, result)]
            if named:
                return min(named, key=lambda t: abs(t.timestamp - result.received_at))
            # Otherwise only commit when every candidate agrees on the
            # exception type, so a wrong attribution is impossible.
            if len({t.exception_type for t in window}) == 1:
                return min(window, key=lambda t: abs(t.timestamp - result.received_at))

    # 3. The exception type name appears in the body.
    if body:
        for trace in traces:
            if trace.exception_type and trace.exception_type in body:
                return trace
    return None


# Words that appear in handler names and route paths without identifying either.
# Without this, `get_user` and `/files` "match" on the shared token `get`, and a
# trace from one endpoint gets attributed to the other.
_GENERIC_TOKENS = frozenset(
    {
        "get", "post", "put", "patch", "delete", "head", "options",
        "api", "v1", "v2", "v3", "handler", "handle", "endpoint", "route",
        "read", "write", "list", "create", "update", "fetch", "index",
        "view", "async", "def", "func", "main", "app", "id",
    }
)


def _tokens(text: str) -> set[str]:
    """Split an identifier or path into comparable, *identifying* word tokens.

    Generic verbs are dropped: they are noise for deciding which endpoint a
    stack frame belongs to, and treating them as signal causes cross-operation
    trace mis-attribution.
    """
    return {
        t
        for t in re.split(r"[^a-z0-9]+", text.lower())
        if len(t) > 2 and t not in _GENERIC_TOKENS
    }


def _operation_tokens(operation) -> set[str]:
    """Words identifying an operation: its path segments and operationId."""
    return _tokens(
        operation.path.replace("{", " ").replace("}", " ")
    ) | _tokens(operation.operation_id or "")


def _names_operation(trace: StackTrace, result) -> bool:
    """True if the trace's application frames look like this operation's handler.

    Web frameworks name the handler function after the route far more often
    than not (`get_user` for `/users/{id}`), so overlapping tokens between the
    frame's function name and the request path are a strong identity signal.
    """
    wanted = _operation_tokens(result.case.operation)
    if not wanted:
        return False
    return any(_tokens(f.function) & wanted for f in trace.app_frames)


def _names_other_operation(trace: StackTrace, result) -> bool:
    """True if the trace clearly belongs to a *different* endpoint's handler.

    Under concurrency a trace can land inside this request's window purely by
    coincidence. When its culprit function shares no words with this operation
    but the frame does name something route-like, attributing it here would
    point the reader at unrelated code.
    """
    culprit = trace.culprit
    if culprit is None or not culprit.function:
        return False

    mine = _operation_tokens(result.case.operation)
    theirs = _tokens(culprit.function)
    if not mine or not theirs:
        return False
    # Overlap means it plausibly is ours; no overlap is only meaningful as
    # evidence against when the handler name carries real words to compare.
    return not (mine & theirs)


def _signature(finding: Finding, trace: StackTrace | None) -> str:
    """Identity for grouping. Two findings share a cluster iff this matches.

    The operation is always part of the key. A shared helper can raise the same
    exception for several endpoints, and merging those would produce a report
    whose title names one endpoint while its reproducer hits another — which is
    worse than no clustering at all.
    """
    if trace is not None:
        return f"{trace.signature}#{finding.operation_key}"

    parts = [finding.kind, finding.operation_key]
    if finding.result.status is not None:
        parts.append(str(finding.result.status))
    if finding.result.transport_error:
        parts.append(finding.result.transport_error.split(":")[0])
    # Include a normalized slice of the body so two different errors on the
    # same endpoint don't collapse into one cluster.
    if finding.result.body_text:
        parts.append(normalize(finding.result.body_text)[:120])

    digest = hashlib.sha256("|".join(parts).encode()).hexdigest()[:12]
    return f"{finding.kind}@{digest}"
