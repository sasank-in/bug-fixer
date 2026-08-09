"""Generate schema-conforming values from JSON Schema fragments.

This is the "valid baseline" side of the fuzzer. Mutations in `mutators.py`
take these values and deliberately break them.
"""

from __future__ import annotations

import random
import string
from typing import Any

# Keep generated structures small; deep nesting explodes the request count
# without finding meaningfully different bugs.
MAX_DEPTH = 4
MAX_ARRAY_ITEMS = 3


def generate(schema: dict[str, Any] | None, rng: random.Random, depth: int = 0) -> Any:
    """Produce a value that satisfies `schema` on a best-effort basis."""
    if not schema or depth > MAX_DEPTH:
        return _scalar(rng)

    if "const" in schema:
        return schema["const"]
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return rng.choice(enum)
    if "default" in schema and rng.random() < 0.3:
        return schema["default"]
    if (
        isinstance(schema.get("examples"), list)
        and schema["examples"]
        and rng.random() < 0.3
    ):
        return rng.choice(schema["examples"])
    if "example" in schema and rng.random() < 0.3:
        return schema["example"]

    for combinator in ("oneOf", "anyOf"):
        options = schema.get(combinator)
        if isinstance(options, list) and options:
            return generate(rng.choice(options), rng, depth + 1)
    if isinstance(schema.get("allOf"), list) and schema["allOf"]:
        merged: dict[str, Any] = {"type": "object", "properties": {}, "required": []}
        for part in schema["allOf"]:
            if not isinstance(part, dict):
                continue
            merged["properties"].update(part.get("properties") or {})
            merged["required"].extend(part.get("required") or [])
        return generate(merged, rng, depth)

    schema_type = schema.get("type")
    if isinstance(schema_type, list):
        schema_type = rng.choice([t for t in schema_type if t != "null"] or ["null"])
    if schema_type is None:
        schema_type = "object" if "properties" in schema else "string"

    handler = _HANDLERS.get(schema_type)
    return handler(schema, rng, depth) if handler else _scalar(rng)


def _gen_object(schema: dict[str, Any], rng: random.Random, depth: int) -> dict[str, Any]:
    properties = schema.get("properties") or {}
    required = set(schema.get("required") or [])
    out: dict[str, Any] = {}
    for name, subschema in properties.items():
        # Always include required fields; include optional ones ~70% of the time
        # so the target sees a realistic mix of sparse and full payloads.
        if name in required or rng.random() < 0.7:
            out[name] = generate(
                subschema if isinstance(subschema, dict) else {}, rng, depth + 1
            )
    return out


def _gen_array(schema: dict[str, Any], rng: random.Random, depth: int) -> list[Any]:
    items = schema.get("items")
    low = max(int(schema.get("minItems", 1) or 0), 0)
    high = min(int(schema.get("maxItems", MAX_ARRAY_ITEMS) or MAX_ARRAY_ITEMS), 10)
    count = rng.randint(low, max(low, high))
    subschema = items if isinstance(items, dict) else {}
    return [generate(subschema, rng, depth + 1) for _ in range(count)]


def _gen_string(schema: dict[str, Any], rng: random.Random, _depth: int) -> str:
    fmt = schema.get("format")
    if fmt in _FORMATS:
        return _FORMATS[fmt](rng)
    low = max(int(schema.get("minLength", 4) or 0), 0)
    high = min(int(schema.get("maxLength", 12) or 12), 64)
    length = rng.randint(low, max(low, high))
    alphabet = string.ascii_letters + string.digits
    return "".join(rng.choice(alphabet) for _ in range(length))


def _gen_integer(schema: dict[str, Any], rng: random.Random, _depth: int) -> int:
    low = schema.get("minimum", schema.get("exclusiveMinimum", 0))
    high = schema.get("maximum", schema.get("exclusiveMaximum", 1000))
    try:
        low, high = int(low), int(high)
    except (TypeError, ValueError):
        low, high = 0, 1000
    if low > high:
        low, high = high, low
    value = rng.randint(low, high)
    multiple = schema.get("multipleOf")
    if isinstance(multiple, int) and multiple > 0:
        value -= value % multiple
    return value


def _gen_number(schema: dict[str, Any], rng: random.Random, _depth: int) -> float:
    low = schema.get("minimum", schema.get("exclusiveMinimum", 0))
    high = schema.get("maximum", schema.get("exclusiveMaximum", 1000))
    try:
        low, high = float(low), float(high)
    except (TypeError, ValueError):
        low, high = 0.0, 1000.0
    if low > high:
        low, high = high, low
    return round(rng.uniform(low, high), 4)


def _gen_boolean(_schema: dict[str, Any], rng: random.Random, _depth: int) -> bool:
    return rng.random() < 0.5


def _gen_null(*_args: Any) -> None:
    return None


_HANDLERS = {
    "object": _gen_object,
    "array": _gen_array,
    "string": _gen_string,
    "integer": _gen_integer,
    "number": _gen_number,
    "boolean": _gen_boolean,
    "null": _gen_null,
}


def _rand_hex(rng: random.Random, n: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


_FORMATS = {
    "uuid": lambda r: "-".join(
        _rand_hex(r, n) for n in (8, 4, 4, 4, 12)
    ),
    "email": lambda r: f"{_rand_hex(r, 6)}@example.com",
    "hostname": lambda r: f"host-{_rand_hex(r, 4)}.example.com",
    "ipv4": lambda r: ".".join(str(r.randint(0, 255)) for _ in range(4)),
    "ipv6": lambda r: ":".join(_rand_hex(r, 4) for _ in range(8)),
    "uri": lambda r: f"https://example.com/{_rand_hex(r, 6)}",
    "url": lambda r: f"https://example.com/{_rand_hex(r, 6)}",
    "date": lambda r: f"{r.randint(1970, 2030):04d}-{r.randint(1, 12):02d}-{r.randint(1, 28):02d}",
    "date-time": lambda r: (
        f"{r.randint(1970, 2030):04d}-{r.randint(1, 12):02d}-{r.randint(1, 28):02d}"
        f"T{r.randint(0, 23):02d}:{r.randint(0, 59):02d}:{r.randint(0, 59):02d}Z"
    ),
    "password": lambda r: _rand_hex(r, 12),
    "byte": lambda r: _rand_hex(r, 8),
}


def _scalar(rng: random.Random) -> Any:
    return rng.choice([0, 1, -1, "", "x", True, False, None])
