"""Deterministic security-payload sweep.

Random mutation is good at finding crashes: almost any garbage triggers an
unhandled `KeyError`, so the specific value barely matters. Security oracles are
the opposite — they only fire when one *particular* payload reaches a sink.
`{{7*7}}` proves template injection; nothing else does.

Sampling those payloads at random makes detection a lottery. With 22 hostile
strings and a ~1/2 chance of targeting a given query parameter, a specific
payload arrives with probability ~1/44 per case: 37% after 20 cases, 50% after
30. A security check that silently runs half the time is not a security check,
and a clean run means very little.

This module removes the luck. Every payload below is sent to every string-ish
parameter exactly once, so coverage is a guarantee rather than a probability,
and it is identical on every run regardless of seed. The cost is bounded and
predictable: `targets * payloads` requests, independent of `--cases`.

Random mutation still runs alongside this — it explores value space the sweep
never will. The two are complementary, not alternatives.
"""

from __future__ import annotations

import copy
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from autoqa.fuzz.engine import CaseBuilder, TestCase
from autoqa.fuzz.mutators import Mutation
from autoqa.spec.parser import Operation


@dataclass(frozen=True)
class Payload:
    """One security probe, paired with what a hit would mean."""

    tag: str
    value: str
    # Short note used in the report so a finding explains itself.
    intent: str


# Grouped by the vulnerability class each one probes. Kept tight on purpose:
# every entry multiplies against every parameter of every operation, and a
# bloated list buys marginal coverage at linear cost.
SECURITY_PAYLOADS: tuple[Payload, ...] = (
    # -- path traversal ----------------------------------------------------
    Payload("traversal_unix", "../../../../etc/passwd", "reads a known Unix file"),
    Payload("traversal_win", "..\\..\\..\\windows\\win.ini", "reads a known Windows file"),
    Payload("traversal_encoded", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd", "traversal past a decoder"),
    Payload("traversal_absolute", "/etc/passwd", "absolute path with no traversal"),
    # -- injection into an interpreter ------------------------------------
    Payload("sqli_tautology", "' OR '1'='1", "always-true SQL predicate"),
    Payload("sqli_terminator", '"; DROP TABLE users; --', "statement break out"),
    Payload("sqli_union", "' UNION SELECT NULL--", "column-count probe"),
    Payload("template_injection", "{{7*7}}", "server-side template evaluation"),
    Payload("expression_injection", "${7*7}", "expression-language evaluation"),
    Payload("jndi_lookup", "${jndi:ldap://127.0.0.1/a}", "Log4Shell-style lookup"),
    Payload("command_substitution", "$(echo 49)", "shell substitution"),
    Payload("command_chain", "; echo 49", "shell command chaining"),
    # -- output-context injection -----------------------------------------
    Payload("xss_script", "<script>alert(1)</script>", "unescaped HTML in output"),
    Payload("xss_attribute", '" onmouseover="alert(1)', "attribute break out"),
    Payload("header_injection", "\r\nX-Injected: yes", "CRLF header splitting"),
    # -- parser and encoding abuse ----------------------------------------
    Payload("null_byte", "\x00truncated", "C-string truncation"),
    Payload("format_string", "%s%s%s%n", "format-string handling"),
    Payload("xxe_entity", '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>', "XML entity expansion"),
    Payload("nosql_operator", '{"$gt": ""}', "NoSQL operator injection"),
)


@dataclass(frozen=True)
class SweepTarget:
    """One place a payload can be injected."""

    kind: str  # "query" | "path" | "header" | "body"
    name: str

    def label(self) -> str:
        return {
            "query": f"?{self.name}",
            "path": f"{{{self.name}}}",
            "header": f"header:{self.name}",
            "body": self.name,
        }[self.kind]


# JSON Schema types worth probing with a string payload. Injecting into an
# integer field usually just trips type validation and never reaches a sink.
_STRINGISH = {"string", None, "", "any"}


def _is_stringish(schema: dict[str, Any] | None) -> bool:
    if not schema:
        return True  # untyped: could be anything, so worth probing
    declared = schema.get("type")
    if isinstance(declared, list):
        return any(t in _STRINGISH for t in declared)
    return declared in _STRINGISH


def targets_for(operation: Operation) -> list[SweepTarget]:
    """Every injectable string-ish location this operation exposes."""
    out: list[SweepTarget] = []

    for prm in operation.parameters:
        if prm.location in ("query", "path", "header") and _is_stringish(prm.schema):
            out.append(SweepTarget(prm.location, prm.name))

    body = operation.body_schema or {}
    properties = body.get("properties")
    if isinstance(properties, dict):
        for name, subschema in properties.items():
            if _is_stringish(subschema if isinstance(subschema, dict) else None):
                out.append(SweepTarget("body", name))
    elif body.get("type") == "object" or "additionalProperties" in body:
        # A free-form object declares no properties to target, but handlers
        # still read keys out of it. Probe the names the demo-style handlers
        # and most CRUD APIs actually use.
        for name in ("id", "name", "path", "file", "query", "search"):
            out.append(SweepTarget("body", name))

    return out


def estimate(operations: list[Operation]) -> int:
    """Request count this sweep will add. Shown before it runs."""
    return sum(len(targets_for(op)) for op in operations) * len(SECURITY_PAYLOADS)


def build_sweep_cases(
    operations: list[Operation], seed: int
) -> Iterator[TestCase]:
    """Yield one case per (operation, target, payload).

    The surrounding request is a valid baseline so the payload is the only
    hostile element — same single-mutation discipline the random path uses, so
    a failure is unambiguously attributable to the payload.
    """
    import random

    for index, operation in enumerate(operations):
        targets = targets_for(operation)
        if not targets:
            continue
        # Seeded per operation, matching build_cases, so the *surrounding*
        # request is reproducible. The payloads themselves are not random.
        rng = random.Random(seed + index * 7919)
        builder = CaseBuilder(operation, rng)

        for target in targets:
            for payload in SECURITY_PAYLOADS:
                base = builder.baseline()
                case = _inject(base, target, payload)
                if case is not None:
                    yield case


def _inject(base: TestCase, target: SweepTarget, payload: Payload) -> TestCase | None:
    """Place `payload` at `target` in a copy of `base`."""
    query = dict(base.query)
    headers = dict(base.headers)
    body = copy.deepcopy(base.body)
    path = base.path

    if target.kind == "query":
        query[target.name] = payload.value

    elif target.kind == "header":
        # CR/LF in a header value breaks the client before it reaches the
        # target, so the header-injection probe is neutered here by design;
        # it stays meaningful in query and body positions.
        headers[target.name] = payload.value.replace("\r", "").replace("\n", "")

    elif target.kind == "path":
        from urllib.parse import quote

        placeholder = f"{{{target.name}}}"
        if placeholder in base.operation.path:
            # Rebuild from the template: `base.path` already has values filled in.
            path = base.operation.path.replace(
                placeholder, quote(payload.value, safe="")
            )
            # Fill any remaining placeholders the same way the engine does.
            while "{" in path and "}" in path:
                start = path.index("{")
                end = path.index("}", start)
                path = path[:start] + "1" + path[end + 1 :]
        else:
            return None

    elif target.kind == "body":
        if not isinstance(body, dict):
            body = {}
        body[target.name] = payload.value

    return TestCase(
        operation=base.operation,
        method=base.method,
        path=path,
        query=query,
        headers=headers,
        body=body,
        mutations=[Mutation(payload.tag, target.label(), payload.value)],
        is_baseline=False,
        seed=base.seed,
    )
