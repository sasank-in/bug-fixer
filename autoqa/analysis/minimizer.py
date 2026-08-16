"""Shrink a failing test case to the smallest input that still fails.

A 10KB payload that triggers a 500 is a bad bug report. The same bug reduced to
`{"age": -1}` is a good one. This runs a delta-debugging pass against the live
target, so it costs real requests — it is applied only to cluster exemplars.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import replace
from typing import Any

from autoqa.analysis.normalize import normalize
from autoqa.fuzz.engine import TestCase
from autoqa.runner.executor import Result

# A predicate answers "does this case still reproduce the bug?"
Predicate = Callable[[TestCase], Awaitable[bool]]

MAX_ROUNDS = 6

# Ceiling on live requests spent shrinking one reproducer. Each round offers
# up to ~18 candidates and every one is a sequential round-trip, so an
# unbounded search can spend 100+ requests on a single finding — and when the
# endpoint under test hangs, each of those costs the full --timeout. Shrinking
# is a nicety; the unshrunk reproducer still reproduces, so it is right to stop
# early rather than let one finding dominate the campaign.
MAX_PROBES_PER_CASE = 40


def is_minimizable(original: Result) -> bool:
    """Whether shrinking this failure can produce a trustworthy reproducer.

    Transport failures (resets, timeouts) carry no body and no status — the
    only signal is the error class, which is far too coarse to tell "still the
    same bug" from "empty request also fails". Minimizing them reliably strips
    the very input under test and yields a reproducer that does not reproduce,
    which is worse than shipping the original request unshrunk.
    """
    return not original.transport_error


def same_failure(original: Result) -> Callable[[Result], bool]:
    """Build a matcher for 'this is still the same failure as the original'.

    Status alone is far too loose: an endpoint that 500s on a missing file and
    500s on a SQL error would let the minimizer strip the input that caused the
    bug we're actually reporting and still call it a match. So the error body
    must stay recognisably the same too.
    """
    target_status = original.status
    target_error = (original.transport_error or "").split(":")[0]
    target_fingerprint = _body_fingerprint(original.body_text)

    def matches(candidate: Result) -> bool:
        if target_error:
            return (candidate.transport_error or "").split(":")[0] == target_error
        if candidate.status != target_status:
            return False
        if candidate.transport_error:
            return False
        # If the original had no distinguishing body, status is all we have.
        if not target_fingerprint:
            return True
        return _body_fingerprint(candidate.body_text) == target_fingerprint

    return matches


def _body_fingerprint(body: str) -> str:
    """Reduce an error body to the shape of the error, ignoring its operands.

    Shares `normalize` with the clusterer so "same failure" means the same
    thing during minimization as it does during grouping.
    """
    if not body:
        return ""
    return " ".join(normalize(body[:400]).split())


async def minimize(
    case: TestCase, still_fails: Predicate, max_probes: int = MAX_PROBES_PER_CASE
) -> TestCase:
    """Greedily simplify a case while `still_fails` keeps returning True.

    Stops at `max_probes` live requests. Returning a partially-shrunk case is
    fine — every intermediate value was itself confirmed to still fail, so the
    result reproduces regardless of where the search stopped.
    """
    current = case
    probes = 0

    for _ in range(MAX_ROUNDS):
        simplified = False

        for candidate in _candidates(current):
            if probes >= max_probes:
                return current
            probes += 1
            if await still_fails(candidate):
                current = candidate
                simplified = True
                break

        if not simplified:
            break

    return current


def _candidates(case: TestCase) -> list[TestCase]:
    """Ordered simplification attempts, biggest reduction first."""
    out: list[TestCase] = []

    # 1. Drop the body entirely.
    if case.body is not None:
        out.append(replace(case, body=None))

    # 2. Drop optional query params one at a time.
    for name in list(case.query):
        reduced = dict(case.query)
        del reduced[name]
        out.append(replace(case, query=reduced))

    # 3. Drop headers.
    for name in list(case.headers):
        reduced = dict(case.headers)
        del reduced[name]
        out.append(replace(case, headers=reduced))

    # 4. Prune the body structurally.
    out.extend(replace(case, body=b) for b in _shrink(case.body))

    return out


def _shrink(value: Any) -> list[Any]:
    """Structural reductions of a JSON-ish value, largest reduction first."""
    if isinstance(value, dict) and value:
        out: list[Any] = []
        if len(value) > 1:
            # Halve the object first — converges much faster than one-at-a-time.
            keys = list(value)
            mid = len(keys) // 2
            out.append({k: value[k] for k in keys[:mid]})
            out.append({k: value[k] for k in keys[mid:]})
        for key in list(value):
            reduced = dict(value)
            del reduced[key]
            out.append(reduced)
        # Then try simplifying each remaining value in place.
        for key, inner in value.items():
            for smaller in _shrink(inner):
                candidate = dict(value)
                candidate[key] = smaller
                out.append(candidate)
        return out

    if isinstance(value, list) and value:
        out = []
        if len(value) > 1:
            mid = len(value) // 2
            out.append(value[:mid])
            out.append(value[mid:])
        out.append([])
        for i in range(len(value)):
            out.append(value[:i] + value[i + 1 :])
        return out

    if isinstance(value, str) and len(value) > 1:
        # Halve repeatedly, then try the empty string.
        return [value[: len(value) // 2], value[:1], ""]

    if isinstance(value, bool):
        return []
    if isinstance(value, int) and value not in (0, 1, -1):
        return [0, 1, -1]
    if isinstance(value, float) and value != 0.0:
        return [0.0]

    return []
