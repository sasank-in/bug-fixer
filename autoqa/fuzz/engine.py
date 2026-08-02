"""Build concrete HTTP test cases from operations."""

from __future__ import annotations

import copy
import random
from dataclasses import dataclass, field
from typing import Any, Iterator
from urllib.parse import quote

from autoqa.fuzz import mutators
from autoqa.fuzz.generators import generate
from autoqa.spec.parser import Operation, Parameter


@dataclass
class TestCase:
    """A fully-realised request, reproducible from its own fields."""

    operation: Operation
    method: str
    path: str
    query: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    body: Any = None
    mutations: list[mutators.Mutation] = field(default_factory=list)
    is_baseline: bool = False
    seed: int = 0

    @property
    def label(self) -> str:
        if self.is_baseline:
            return "baseline"
        return ", ".join(m.describe() for m in self.mutations) or "unmutated"


class CaseBuilder:
    """Produces baseline and mutated test cases for a single operation."""

    def __init__(self, operation: Operation, rng: random.Random) -> None:
        self.op = operation
        self.rng = rng

    def baseline(self) -> TestCase:
        """A request that should succeed. Establishes what 'normal' looks like."""
        query, headers, path_values = self._valid_params()
        body = (
            generate(self.op.body_schema, self.rng)
            if self.op.body_schema is not None
            else None
        )
        return TestCase(
            operation=self.op,
            method=self.op.method,
            path=self._render_path(path_values),
            query=query,
            headers=headers,
            body=body,
            is_baseline=True,
            seed=self.rng.randint(0, 2**31),
        )

    def mutated(self) -> TestCase:
        """One request with exactly one mutation applied, so blame is unambiguous."""
        query, headers, path_values = self._valid_params()
        body = (
            generate(self.op.body_schema, self.rng)
            if self.op.body_schema is not None
            else None
        )
        applied: list[mutators.Mutation] = []

        targets = self._mutation_targets(query, headers, path_values, body)
        if not targets:
            return TestCase(
                operation=self.op,
                method=self.op.method,
                path=self._render_path(path_values),
                query=query,
                headers=headers,
                body=body,
                seed=self.rng.randint(0, 2**31),
            )

        choice = self.rng.choice(targets)

        if choice == "query" and query:
            name = self.rng.choice(list(query))
            mutator = mutators.pick_mutator(query[name], self.rng)
            value, tag = mutator(query[name], self.rng)
            query[name] = value
            applied.append(mutators.Mutation(tag, f"?{name}", value))

        elif choice == "header" and headers:
            name = self.rng.choice(list(headers))
            value, tag = mutators.mutate_string(headers[name], self.rng)
            # Header values must stay str; CR/LF would break the client itself
            # rather than reaching the target, so strip them here.
            headers[name] = str(value).replace("\r", "").replace("\n", "")
            applied.append(mutators.Mutation(tag, f"header:{name}", headers[name]))

        elif choice == "path" and path_values:
            name = self.rng.choice(list(path_values))
            value, tag = mutators.mutate_string(path_values[name], self.rng)
            path_values[name] = value
            applied.append(mutators.Mutation(tag, f"{{{name}}}", value))

        elif choice == "body_leaf":
            result = mutators.mutate_leaf(body, self.rng, "$body")
            if result:
                body, mutation = result
                applied.append(mutation)

        elif choice == "body_drop":
            required = list((self.op.body_schema or {}).get("required") or [])
            result = mutators.drop_required_field(body, required, self.rng)
            if result:
                body, mutation = result
                applied.append(mutation)

        elif choice == "body_unknown":
            body, mutation = mutators.inject_unknown_field(body, self.rng)
            applied.append(mutation)

        elif choice == "body_replace":
            value, tag = mutators.mutate_type_confusion(body, self.rng)
            body = value
            applied.append(mutators.Mutation(tag, "$body", value))

        return TestCase(
            operation=self.op,
            method=self.op.method,
            path=self._render_path(path_values),
            query=query,
            headers=headers,
            body=body,
            mutations=applied,
            seed=self.rng.randint(0, 2**31),
        )

    # -- internals ---------------------------------------------------------

    def _mutation_targets(
        self,
        query: dict[str, Any],
        headers: dict[str, str],
        path_values: dict[str, Any],
        body: Any,
    ) -> list[str]:
        targets: list[str] = []
        if query:
            targets += ["query"] * 3
        if headers:
            targets.append("header")
        if path_values:
            targets += ["path"] * 2
        if isinstance(body, dict):
            targets += ["body_leaf"] * 3 + ["body_drop", "body_unknown", "body_replace"]
        elif body is not None:
            targets += ["body_leaf", "body_replace"]
        return targets

    def _valid_params(self) -> tuple[dict[str, Any], dict[str, str], dict[str, Any]]:
        query: dict[str, Any] = {}
        headers: dict[str, str] = {}
        path_values: dict[str, Any] = {}

        for prm in self.op.parameters:
            # Skip optional params sometimes so we exercise defaulting paths.
            if not prm.required and self.rng.random() < 0.35:
                continue
            value = generate(prm.schema, self.rng)
            if prm.location == "query":
                query[prm.name] = value
            elif prm.location == "header":
                headers[prm.name] = str(value)
            elif prm.location == "path":
                path_values[prm.name] = value

        return query, headers, path_values

    def _render_path(self, values: dict[str, Any]) -> str:
        path = self.op.path
        for name, value in values.items():
            path = path.replace(f"{{{name}}}", quote(str(value), safe=""))
        # Any placeholder the spec declared but we didn't fill gets a safe stub,
        # otherwise the literal "{id}" would 404 and mask real findings.
        while "{" in path and "}" in path:
            start = path.index("{")
            end = path.index("}", start)
            path = path[:start] + "1" + path[end + 1 :]
        return path


def build_cases(
    operations: list[Operation],
    cases_per_operation: int,
    seed: int,
) -> Iterator[TestCase]:
    """Yield one baseline plus N mutated cases for every operation."""
    for index, op in enumerate(operations):
        # Derive a per-operation seed so a single operation can be re-run
        # deterministically without replaying the whole campaign.
        rng = random.Random(seed + index * 7919)
        builder = CaseBuilder(op, rng)
        yield builder.baseline()
        for _ in range(cases_per_operation):
            yield builder.mutated()
