"""Mutation strategies.

Each mutator takes a valid value and returns a deliberately hostile variant,
along with a tag describing what was done. Tags flow through to the report so
a finding reads as "boundary_int on ?limit -> 500" rather than a raw payload
diff the user has to decode themselves.
"""

from __future__ import annotations

import copy
import random
from dataclasses import dataclass
from typing import Any, Callable

# Values that break naive parsers, injection sinks, and integer handling.
# Kept deliberately small and high-yield: every extra entry multiplies request
# count across every field in every operation.
HOSTILE_STRINGS: tuple[str, ...] = (
    "",
    " ",
    "null",
    "undefined",
    "0",
    "-1",
    "A" * 4096,
    "%s%s%s%n",
    "../../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "' OR '1'='1",
    '"; DROP TABLE users; --',
    "<script>alert(1)</script>",
    "{{7*7}}",
    "${jndi:ldap://127.0.0.1/a}",
    "\x00truncated",
    "🔥💥‮﻿",
    "%00",
    "%2e%2e%2f",
    "\r\nX-Injected: yes",
    "-1e308",
    "NaN",
)

BOUNDARY_INTS: tuple[int, ...] = (
    0,
    -1,
    1,
    2**31 - 1,
    -(2**31),
    2**53,
    2**63 - 1,
    -(2**63),
    10**20,
)

BOUNDARY_FLOATS: tuple[float, ...] = (0.0, -0.0, 1e308, -1e308, 1e-308)

TYPE_CONFUSION: tuple[Any, ...] = (
    None,
    True,
    0,
    -1,
    "string-where-number-expected",
    [],
    {},
    [1, 2, 3],
    {"nested": {"deep": True}},
)


@dataclass(frozen=True)
class Mutation:
    """A single applied mutation, described well enough to reproduce it."""

    tag: str
    target: str
    value: Any

    def describe(self) -> str:
        preview = repr(self.value)
        if len(preview) > 60:
            preview = preview[:57] + "..."
        return f"{self.tag} on {self.target} = {preview}"


Mutator = Callable[[Any, random.Random], tuple[Any, str]]


def mutate_string(_value: Any, rng: random.Random) -> tuple[Any, str]:
    return rng.choice(HOSTILE_STRINGS), "hostile_string"


def mutate_boundary_int(_value: Any, rng: random.Random) -> tuple[Any, str]:
    return rng.choice(BOUNDARY_INTS), "boundary_int"


def mutate_boundary_float(_value: Any, rng: random.Random) -> tuple[Any, str]:
    return rng.choice(BOUNDARY_FLOATS), "boundary_float"


def mutate_type_confusion(value: Any, rng: random.Random) -> tuple[Any, str]:
    candidates = [c for c in TYPE_CONFUSION if type(c) is not type(value)]
    return rng.choice(candidates or list(TYPE_CONFUSION)), "type_confusion"


def mutate_oversized(_value: Any, rng: random.Random) -> tuple[Any, str]:
    size = rng.choice([10_000, 100_000])
    return "B" * size, "oversized_payload"


def mutate_deep_nesting(_value: Any, _rng: random.Random) -> tuple[Any, str]:
    node: Any = {"end": True}
    for _ in range(200):
        node = {"n": node}
    return node, "deep_nesting"


def mutate_huge_array(_value: Any, _rng: random.Random) -> tuple[Any, str]:
    return list(range(10_000)), "huge_array"


def mutate_negate(value: Any, _rng: random.Random) -> tuple[Any, str]:
    if isinstance(value, bool):
        return (not value), "negate"
    if isinstance(value, (int, float)):
        return -value, "negate"
    if isinstance(value, str):
        return value[::-1], "negate"
    return value, "negate"


_SCALAR_MUTATORS: tuple[Mutator, ...] = (
    mutate_string,
    mutate_boundary_int,
    mutate_boundary_float,
    mutate_type_confusion,
    mutate_oversized,
    mutate_negate,
)

_CONTAINER_MUTATORS: tuple[Mutator, ...] = (
    mutate_type_confusion,
    mutate_deep_nesting,
    mutate_huge_array,
)


def pick_mutator(value: Any, rng: random.Random) -> Mutator:
    """Choose a mutator biased toward the value's actual type."""
    if isinstance(value, (dict, list)):
        return rng.choice(_CONTAINER_MUTATORS)
    if isinstance(value, bool):
        return rng.choice((mutate_type_confusion, mutate_negate, mutate_string))
    if isinstance(value, int):
        return rng.choice(
            (mutate_boundary_int, mutate_type_confusion, mutate_string, mutate_negate)
        )
    if isinstance(value, float):
        return rng.choice((mutate_boundary_float, mutate_type_confusion, mutate_string))
    return rng.choice(_SCALAR_MUTATORS)


# -- structural mutations on whole payloads --------------------------------


def drop_required_field(
    payload: dict[str, Any], required: list[str], rng: random.Random
) -> tuple[dict[str, Any], Mutation] | None:
    """Remove a required field to test the target's validation layer."""
    present = [f for f in required if f in payload]
    if not present:
        return None
    field = rng.choice(present)
    out = copy.deepcopy(payload)
    del out[field]
    return out, Mutation("drop_required", field, "<removed>")


def inject_unknown_field(
    payload: dict[str, Any], rng: random.Random
) -> tuple[dict[str, Any], Mutation]:
    """Add an unexpected field. Catches mass-assignment and strict-mode bugs."""
    name = rng.choice(
        ["__proto__", "constructor", "is_admin", "role", "_id", "$where", "id"]
    )
    value = rng.choice([True, "admin", {"polluted": True}, 999999])
    out = copy.deepcopy(payload)
    out[name] = value
    return out, Mutation("unknown_field", name, value)


def mutate_leaf(
    payload: Any, rng: random.Random, path: str = "$"
) -> tuple[Any, Mutation] | None:
    """Pick one random leaf anywhere in the payload and corrupt it."""
    leaves: list[tuple[list[Any], str]] = []

    def walk(node: Any, trail: list[Any], label: str) -> None:
        if isinstance(node, dict):
            if not node:
                leaves.append((trail, label))
            for k, v in node.items():
                walk(v, trail + [k], f"{label}.{k}")
        elif isinstance(node, list):
            if not node:
                leaves.append((trail, label))
            for i, v in enumerate(node):
                walk(v, trail + [i], f"{label}[{i}]")
        else:
            leaves.append((trail, label))

    walk(payload, [], path)
    if not leaves:
        return None

    trail, label = rng.choice(leaves)
    out = copy.deepcopy(payload)

    # Navigate to the leaf's parent so we can overwrite in place.
    node = out
    for step in trail[:-1]:
        node = node[step]

    original = node[trail[-1]] if trail else out
    mutator = pick_mutator(original, rng)
    new_value, tag = mutator(original, rng)

    if not trail:
        return new_value, Mutation(tag, label, new_value)
    node[trail[-1]] = new_value
    return out, Mutation(tag, label, new_value)
