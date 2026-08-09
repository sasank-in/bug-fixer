"""Shared HTTP encoding helpers.

The executor sends requests and the reporter renders reproducers of those same
requests. Both must agree byte-for-byte — a reproducer that encodes differently
than the request it describes will not reproduce the bug. Keeping the encoding
in one place is what makes that guarantee structural rather than a convention
two modules have to remember to follow.
"""

from __future__ import annotations

import json
from typing import Any

DEFAULT_CONTENT_TYPE = "application/json"


def has_header(headers: dict[str, str], name: str) -> bool:
    """Case-insensitive header presence check, per RFC 9110.

    Header names are case-insensitive, so a plain `in` test would miss a
    spec-declared `content-type` and let a second `Content-Type` be added
    alongside it. httpx joins duplicates with a comma, producing a malformed
    header that the fuzzer would then report as the target's fault.
    """
    lowered = name.lower()
    return any(key.lower() == lowered for key in headers)


def with_default_content_type(headers: dict[str, str]) -> dict[str, str]:
    """Add the JSON content-type only when the caller has not set one."""
    if has_header(headers, "content-type"):
        return dict(headers)
    return {**headers, "Content-Type": DEFAULT_CONTENT_TYPE}


def encode_body(body: Any) -> bytes:
    """Serialize a possibly-hostile body to JSON bytes.

    `allow_nan=True` is deliberate: `Infinity` and `NaN` are not valid JSON,
    which is precisely why they are worth sending — a target that mishandles
    them is a finding. (httpx's own encoder uses `allow_nan=False` and would
    raise before the request left, turning our encoding choice into a bogus
    "connection failure" attributed to the target.)

    For values JSON cannot represent at all, fall back to `repr` so the request
    still carries something hostile rather than failing before it is sent.
    """
    try:
        return json.dumps(body, allow_nan=True).encode("utf-8")
    except (TypeError, ValueError):
        return repr(body).encode("utf-8", "replace")


def json_safe(value: Any) -> Any:
    """Make a possibly-hostile value safe to embed in a JSON report.

    Probes with `allow_nan=False` so non-finite floats become strings rather
    than bare `Infinity`/`NaN` tokens, which strict JSON parsers reject. A
    report consumers cannot parse is not a report.
    """
    try:
        json.dumps(value, allow_nan=False)
        return value
    except (TypeError, ValueError):
        return repr(value)[:2000]
