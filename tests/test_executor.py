"""Executor behaviour, especially body encoding.

The failure mode these guard against: an encoding error on our side being
reported as a transport failure, which blames the target for our bug and
manufactures a finding that does not exist.
"""

import json
import random

import httpx
import pytest

from autoqa.fuzz.engine import CaseBuilder
from autoqa.runner.executor import Executor
from autoqa.runner.http import encode_body
from autoqa.spec.parser import Operation

OP = Operation(operation_id="o", method="POST", path="/x")


def case_with_body(body):
    case = CaseBuilder(OP, random.Random(1)).baseline()
    case.query, case.headers, case.body = {}, {}, body
    return case


# -- encoding --------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        {"a": 1},
        {"nested": {"deep": [1, 2, {"x": None}]}},
        [],
        "plain string",
        0,
        True,
        None,
    ],
)
def test_ordinary_bodies_round_trip(body):
    assert json.loads(encode_body(body).decode()) == body


def test_infinity_is_sent_not_rejected():
    """httpx would raise on inf; we send it because a target that chokes on
    non-standard JSON is exactly the finding we want."""
    assert encode_body({"x": float("inf")}) == b'{"x": Infinity}'


def test_nan_is_sent():
    assert b"NaN" in encode_body({"x": float("nan")})


def test_unserializable_body_falls_back_to_repr():
    encoded = encode_body({1, 2, 3})  # a set has no JSON form
    assert encoded  # must produce something rather than raising
    assert b"1" in encoded


def test_encoding_never_raises_on_mutator_output():
    """Every value the mutators can emit must encode without blowing up."""
    from autoqa.fuzz.mutators import (
        BOUNDARY_FLOATS,
        BOUNDARY_INTS,
        HOSTILE_STRINGS,
        TYPE_CONFUSION,
    )

    for pool in (HOSTILE_STRINGS, BOUNDARY_INTS, BOUNDARY_FLOATS, TYPE_CONFUSION):
        for value in pool:
            encode_body({"field": value})
            encode_body(value)


# -- request construction --------------------------------------------------


async def test_inf_body_reaches_the_server_as_a_real_response():
    """The regression: this used to surface as a bogus connection failure."""
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = request.content
        seen["content_type"] = request.headers.get("content-type")
        return httpx.Response(200, json={"ok": True})

    executor = Executor("http://t")
    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        result = await executor._send(client, case_with_body({"x": float("inf")}))

    assert result.transport_error is None, result.transport_error
    assert result.status == 200
    assert b"Infinity" in seen["body"]
    assert seen["content_type"] == "application/json"


async def test_real_transport_failure_is_still_reported():
    """The fix must not swallow genuine connection problems."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    executor = Executor("http://t")
    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        result = await executor._send(client, case_with_body({"a": 1}))

    assert result.transport_error is not None
    assert "ConnectError" in result.transport_error


async def test_transport_error_has_no_empty_message():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadError("")

    executor = Executor("http://t")
    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        result = await executor._send(client, case_with_body(None))

    assert not result.transport_error.rstrip().endswith(":")


@pytest.mark.parametrize(
    "header_name", ["Content-Type", "content-type", "CONTENT-TYPE", "Content-type"]
)
async def test_caller_content_type_is_not_overridden(header_name):
    """An explicit header must win over our default, whatever its casing.

    Header names are case-insensitive, so a naive dict merge leaves both ours
    and theirs in place and httpx joins them with a comma — a malformed header
    we would then report as the target's fault.
    """
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["ct"] = request.headers.get("content-type")
        return httpx.Response(200)

    case = case_with_body({"a": 1})
    case.headers = {header_name: "application/vnd.custom+json"}

    executor = Executor("http://t")
    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        await executor._send(client, case)

    assert seen["ct"] == "application/vnd.custom+json"
    assert "," not in seen["ct"]


async def test_mutated_content_type_is_sent_verbatim():
    """The regression: a fuzzed content-type used to go out doubled."""
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["ct"] = request.headers.get("content-type")
        return httpx.Response(200)

    case = case_with_body({"a": 1})
    case.headers = {"content-type": "' OR '1'='1"}

    executor = Executor("http://t")
    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        await executor._send(client, case)

    assert seen["ct"] == "' OR '1'='1"


async def test_default_content_type_added_when_absent():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["ct"] = request.headers.get("content-type")
        return httpx.Response(200)

    executor = Executor("http://t")
    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        await executor._send(client, case_with_body({"a": 1}))

    assert seen["ct"] == "application/json"


async def test_auth_header_is_attached():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200)

    executor = Executor("http://t", auth_header=("Authorization", "Bearer tok"))
    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        await executor._send(client, case_with_body(None))

    assert seen["auth"] == "Bearer tok"


async def test_timing_is_recorded():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    executor = Executor("http://t")
    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        result = await executor._send(client, case_with_body(None))

    assert result.sent_at > 0
    assert result.received_at >= result.sent_at
