"""Render campaign results as terminal output, Markdown, and JSON."""

from __future__ import annotations

import json
import shlex
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode

import httpx

from autoqa.analysis.oracles import Severity
from autoqa.campaign import CampaignReport
from autoqa.fuzz.engine import TestCase
from autoqa.runner.http import encode_body, has_header, json_safe

_SEVERITY_ICON = {
    Severity.CRITICAL: "!!",
    Severity.HIGH: "! ",
    Severity.MEDIUM: "~ ",
    Severity.LOW: ". ",
    Severity.INFO: "  ",
}


def request_url(case: TestCase, base_url: str) -> str:
    """The exact URL the executor sent, query encoding included.

    Built through httpx rather than urlencode so the reproducer cannot drift
    from what actually went over the wire. The two disagree on real cases the
    fuzzer produces: a list encodes as repeated `?t=1&t=2` pairs (not one
    bracketed blob), a bool as lowercase `true`, and an empty list drops the
    parameter entirely. A reproducer that doesn't reproduce is worse than none.
    """
    base = base_url.rstrip("/") + case.path
    if not case.query:
        return base
    try:
        return str(httpx.URL(base).copy_merge_params(case.query))
    except httpx.InvalidURL:
        # Some mutations (oversized_payload) build a query httpx refuses to
        # parse — which is itself the finding being reported. Fall back to
        # manual encoding so the report still renders; matching httpx exactly
        # is moot for a URL httpx would not have sent either.
        encoded = urlencode(
            [
                (name, "" if value is None else str(value))
                for name, value in case.query.items()
            ]
        )
        return f"{base}?{encoded}"


# Oversized-payload mutations put 100KB into a single query value. Printed in
# full it is unreadable and, repeated across url/query/curl, dominates the JSON
# report — two such clusters accounted for 600KB of a 673KB file. The elision is
# always labelled with the true length so nothing looks silently complete.
_MAX_URL_DISPLAY = 2000


def _elide(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return f"{text[:limit]}...[truncated, {len(text):,} chars total]"


def curl_for(case: TestCase, base_url: str) -> str:
    """A copy-pasteable reproducer. The single most useful line in the report.

    Very long URLs are elided for display. Such a request is one httpx refused
    to send anyway, so the exact bytes are not reproducible by pasting; the
    `reproducer.query` field in the JSON report keeps the real value.
    """
    url = _elide(request_url(case, base_url), _MAX_URL_DISPLAY)
    parts = ["curl", "-i", "-X", case.method, shlex.quote(url)]
    for name, value in case.headers.items():
        parts += ["-H", shlex.quote(f"{name}: {value}")]
    if case.body is not None:
        # Mirror the executor exactly: only add the default content-type when
        # the case did not carry one, or curl would receive two conflicting
        # -H flags and honour the last, sending a different type than we did.
        if not has_header(case.headers, "content-type"):
            parts += ["-H", shlex.quote("Content-Type: application/json")]
        # Same encoder the executor uses, so the repro carries the exact bytes
        # that were sent (including non-standard Infinity/NaN).
        payload = encode_body(case.body).decode("utf-8", "replace")
        # Keep the reproducer readable; note the elision rather than silently cutting.
        if len(payload) > 2000:
            payload = payload[:2000] + f'... /* truncated, {len(payload)} bytes total */'
        parts += ["-d", shlex.quote(payload)]
    return " ".join(parts)


def render_terminal(report: CampaignReport) -> str:
    cfg = report.config
    lines: list[str] = []
    add = lines.append

    add("")
    add("=" * 72)
    add("  AutoQA campaign report")
    add("=" * 72)
    add(f"  target        {cfg.base_url}")
    add(f"  spec          {cfg.spec_path}")
    add(f"  operations    {len(report.operations)}")
    add(f"  requests      {report.total_requests}")
    add(f"  duration      {report.duration_s:.1f}s")
    add(f"  seed          {cfg.seed}  (reuse to reproduce this exact run)")
    add("")

    histogram = report.status_histogram
    add("  responses     " + "  ".join(f"{k}:{v}" for k, v in histogram.items()))
    add("")

    if report.target_died:
        add("  !! TARGET PROCESS DIED DURING THE RUN")
        add("")

    if not report.clusters:
        add("  No findings. Either the target is solid, or the oracles need")
        add("  tightening for this API. Try --cases 100 for a deeper run.")
        add("")
        add("=" * 72)
        return "\n".join(lines)

    by_severity: dict[Severity, int] = {}
    for cluster in report.clusters:
        by_severity[cluster.severity] = by_severity.get(cluster.severity, 0) + 1
    summary = "  ".join(
        f"{sev.value}:{by_severity[sev]}"
        for sev in sorted(by_severity, key=lambda s: s.rank)
    )
    add(f"  FINDINGS      {len(report.clusters)} distinct issues  ({summary})")
    add(f"                from {len(report.findings)} raw observations")
    add("")
    add("-" * 72)

    for index, cluster in enumerate(report.clusters, start=1):
        icon = _SEVERITY_ICON[cluster.severity]
        add("")
        add(f"{icon} [{index}] {cluster.title}")
        add(f"     severity   {cluster.severity.value}")
        add(f"     seen       {cluster.count}x across {len(cluster.operations)} operation(s)")
        if cluster.mutation_tags:
            add(f"     triggers   {', '.join(cluster.mutation_tags)}")
        add(f"     {cluster.detail}")

        if cluster.trace:
            add("")
            add(f"     root cause {cluster.trace.exception_type}: {cluster.trace.message[:90]}")
            if cluster.trace.culprit:
                add(f"     at         {cluster.trace.culprit.short()}")
            elif cluster.trace.deepest_frame:
                add(
                    f"     at         {cluster.trace.deepest_frame.short()}"
                    f"  (dependency code — no application frame in this trace)"
                )

        case = report.minimized.get(cluster.signature) or cluster.exemplar.result.case
        tag = "minimized repro" if cluster.signature in report.minimized else "repro"
        add("")
        add(f"     {tag}:")
        add(f"       {curl_for(case, cfg.base_url)}")

        if cluster.exemplar.evidence:
            evidence = cluster.exemplar.evidence[0].strip().replace("\n", " ")[:200]
            if evidence:
                add(f"     evidence   {evidence}")
        add("")
        add("-" * 72)

    add("")
    return "\n".join(lines)


def render_markdown(report: CampaignReport) -> str:
    cfg = report.config
    stamp = datetime.fromtimestamp(report.started_at, tz=timezone.utc).isoformat(
        timespec="seconds"
    )
    out: list[str] = []
    add = out.append

    add("# AutoQA Report")
    add("")
    add(f"**Target:** `{cfg.base_url}`  ")
    add(f"**Spec:** `{cfg.spec_path}`  ")
    add(f"**Run at:** {stamp}  ")
    add(f"**Seed:** `{cfg.seed}` — rerun with this seed to reproduce exactly.")
    add("")
    add("| Metric | Value |")
    add("| --- | --- |")
    add(f"| Operations fuzzed | {len(report.operations)} |")
    add(f"| Requests sent | {report.total_requests} |")
    add(f"| Duration | {report.duration_s:.1f}s |")
    add(f"| Distinct issues | {len(report.clusters)} |")
    add(f"| Raw observations | {len(report.findings)} |")
    add("")

    add("## Response distribution")
    add("")
    add("| Status | Count |")
    add("| --- | --- |")
    for status, count in report.status_histogram.items():
        add(f"| `{status}` | {count} |")
    add("")

    if report.target_died:
        add("> **The target process died during this run.** Findings below may be")
        add("> incomplete, and requests after the crash would have failed spuriously.")
        add("")

    if not report.clusters:
        add("## Findings")
        add("")
        add("No issues detected in this run.")
        return "\n".join(out)

    add("## Findings")
    add("")
    for index, cluster in enumerate(report.clusters, start=1):
        add(f"### {index}. {cluster.title}")
        add("")
        add(f"- **Severity:** {cluster.severity.value}")
        add(f"- **Occurrences:** {cluster.count}")
        add(f"- **Affected operations:** {', '.join(f'`{o}`' for o in cluster.operations)}")
        if cluster.mutation_tags:
            add(f"- **Triggering mutations:** {', '.join(cluster.mutation_tags)}")
        add(f"- **Signature:** `{cluster.signature}`")
        add("")
        add(cluster.detail)
        add("")

        if cluster.trace:
            add("**Server-side stack trace**")
            add("")
            if cluster.trace.culprit:
                add(f"Culprit frame: `{cluster.trace.culprit.short()}`")
                add("")
            elif cluster.trace.in_dependency:
                add(
                    "This trace contains no application frames — the failure occurred "
                    "entirely inside the server or a dependency, which usually points at "
                    "malformed input at the protocol layer rather than a bug in your code."
                )
                add("")
            add("```")
            add(cluster.trace.raw[:2000])
            add("```")
            add("")

        case = report.minimized.get(cluster.signature) or cluster.exemplar.result.case
        heading = (
            "**Minimized reproducer**"
            if cluster.signature in report.minimized
            else "**Reproducer**"
        )
        add(heading)
        add("")
        add("```bash")
        add(curl_for(case, cfg.base_url))
        add("```")
        add("")

        if cluster.exemplar.evidence:
            add("**Evidence**")
            add("")
            add("```")
            add(cluster.exemplar.evidence[0][:1200])
            add("```")
            add("")

    return "\n".join(out)


def render_json(report: CampaignReport) -> str:
    payload: dict[str, Any] = {
        "target": report.config.base_url,
        "spec": report.config.spec_path,
        "seed": report.config.seed,
        "started_at": report.started_at,
        "duration_s": round(report.duration_s, 3),
        "operations_fuzzed": len(report.operations),
        "requests_sent": report.total_requests,
        "target_died": report.target_died,
        "status_histogram": report.status_histogram,
        "clusters": [],
    }

    for cluster in report.clusters:
        case = report.minimized.get(cluster.signature) or cluster.exemplar.result.case
        entry: dict[str, Any] = {
            "signature": cluster.signature,
            "kind": cluster.kind,
            "severity": cluster.severity.value,
            "title": cluster.title,
            "detail": cluster.detail,
            "count": cluster.count,
            "operations": cluster.operations,
            "mutation_tags": cluster.mutation_tags,
            "minimized": cluster.signature in report.minimized,
            "reproducer": {
                "curl": curl_for(case, report.config.base_url),
                "method": case.method,
                "path": case.path,
                # The raw values as generated, plus the URL actually sent —
                # str() here would misrepresent lists and bools (see request_url).
                "query": {k: json_safe(v) for k, v in case.query.items()},
                # Elided like the curl line; `query` above holds the full value,
                # so nothing is lost — it just is not stored three times over.
                "url": _elide(
                    request_url(case, report.config.base_url), _MAX_URL_DISPLAY
                ),
                "headers": case.headers,
                "body": json_safe(case.body),
            },
            "observed": {
                "status": cluster.exemplar.result.status,
                "transport_error": cluster.exemplar.result.transport_error,
                "elapsed_ms": round(cluster.exemplar.result.elapsed_ms, 2),
                "body_excerpt": cluster.exemplar.result.body_text[:600],
            },
        }
        if cluster.trace:
            entry["stack_trace"] = {
                "language": cluster.trace.language,
                "exception_type": cluster.trace.exception_type,
                "message": cluster.trace.message,
                "culprit": cluster.trace.culprit.short() if cluster.trace.culprit else None,
                "in_dependency": cluster.trace.in_dependency,
                "frames": [asdict(f) for f in cluster.trace.frames],
            }
        payload["clusters"].append(entry)

    return json.dumps(payload, indent=2, default=str)

