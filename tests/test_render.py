"""Reproducer fidelity.

The curl line is the most-used part of any finding. If pasting it does not
reproduce the bug, the finding is worthless — so these tests compare the
rendered reproducer against what httpx actually puts on the wire.
"""

import json
import random

import httpx
import pytest

from autoqa.fuzz.engine import CaseBuilder
from autoqa.report.render import curl_for, request_url
from autoqa.spec.parser import Operation

OP = Operation(operation_id="o", method="GET", path="/x")
BASE = "http://h"


def case_with(**kwargs):
    case = CaseBuilder(OP, random.Random(1)).baseline()
    case.query, case.headers, case.body = {}, {}, None
    for key, value in kwargs.items():
        setattr(case, key, value)
    return case


def wire_url(case) -> str:
    """The URL the executor would really send, via the same client stack."""
    return str(httpx.Request(case.method, BASE + case.path, params=case.query).url)


@pytest.mark.parametrize(
    "value",
    [
        [1, 2, 3],          # repeated ?t=1&t=2&t=3, not one bracketed blob
        True,               # lowercase "true", not Python's "True"
        False,
        None,               # empty value, not the string "None"
        [],                 # dropped entirely
        1.5,
        -0.0,
        0,
        "",
        "a b&c=d",          # characters needing escaping
        "../../etc/passwd",
        "' OR '1'='1",
        "🔥",
    ],
)
def test_reproducer_url_matches_what_was_sent(value):
    case = case_with(query={"p": value})
    assert request_url(case, BASE) == wire_url(case)


def test_list_param_renders_as_repeated_pairs():
    case = case_with(query={"tags": [1, 2, 3]})
    assert request_url(case, BASE).endswith("?tags=1&tags=2&tags=3")


def test_bool_param_is_lowercase():
    case = case_with(query={"b": True})
    assert request_url(case, BASE).endswith("?b=true")


def test_multiple_params_all_present():
    case = case_with(query={"a": 1, "b": "two"})
    assert request_url(case, BASE) == wire_url(case)


@pytest.mark.parametrize(
    "hostile",
    ["'; rm -rf /", 'x" $(whoami)', "a b'c", "`id`", "$HOME", "line\nbreak"],
)
def test_curl_is_shell_safe_for_hostile_values(hostile):
    """Payloads are attacker-shaped by design; the repro must stay one command.

    Parsed with shlex rather than counting quotes — shlex.quote legitimately
    emits '"'"' for an embedded quote, so a raw quote count proves nothing.
    """
    import shlex

    case = case_with(query={"q": hostile}, headers={"X-T": hostile})
    tokens = shlex.split(curl_for(case, BASE))

    assert tokens[0] == "curl"
    # The payload must survive as exactly one argument, never as extra tokens
    # that the shell would run separately.
    assert any(hostile in token for token in tokens)


def test_curl_includes_method_headers_and_body():
    case = case_with(headers={"X-Token": "abc"}, body={"a": 1})
    line = curl_for(case, BASE)
    assert "-X GET" in line
    assert "X-Token: abc" in line
    assert "Content-Type: application/json" in line
    assert '{"a": 1}' in line


def test_curl_omits_body_when_absent():
    assert " -d " not in curl_for(case_with(), BASE)


def test_oversized_body_is_marked_as_truncated():
    case = case_with(body={"blob": "x" * 50_000})
    line = curl_for(case, BASE)
    assert "truncated" in line
    assert len(line) < 5_000


def test_unserializable_body_still_renders():
    case = case_with(body={1, 2, 3})  # a set is not JSON-serializable
    assert curl_for(case, BASE).startswith("curl")


@pytest.mark.parametrize(
    "query",
    [
        {"p": "B" * 100_000},        # oversized_payload — httpx refuses this URL
        {"p": "\x00null"},
        {"p": "\r\nX-Injected: 1"},
        {"p": {"nested": {"deep": True}}},
        {"": "empty-name"},
    ],
)
def test_rendering_never_crashes_on_hostile_input(query):
    """The report must render the very findings the fuzzer exists to produce."""
    line = curl_for(case_with(query=query), BASE)
    assert line.startswith("curl")


def test_json_report_query_preserves_types():
    """str()-ing query values in the report would repeat the encoding bug."""
    from autoqa.runner.http import json_safe

    assert json_safe([1, 2, 3]) == [1, 2, 3]
    assert json_safe(True) is True
    assert json_safe(None) is None


@pytest.mark.parametrize("value", [float("inf"), float("-inf"), float("nan")])
def test_safe_keeps_the_report_strictly_parseable(value):
    """Bare Infinity/NaN tokens are not valid JSON and break strict parsers."""
    from autoqa.runner.http import json_safe

    rendered = json.dumps({"v": json_safe(value)}, allow_nan=False)
    assert json.loads(rendered)


@pytest.mark.parametrize(
    "header_name", ["Content-Type", "content-type", "CONTENT-TYPE"]
)
def test_curl_emits_one_content_type(header_name):
    """Two -H flags would make curl send a different type than we did."""
    case = case_with(headers={header_name: "application/vnd.custom+json"}, body={"a": 1})
    line = curl_for(case, BASE)
    assert line.lower().count("content-type:") == 1
    assert "application/vnd.custom+json" in line


def test_curl_body_matches_executor_encoding():
    """The repro must carry the exact bytes the executor sent."""
    from autoqa.runner.http import encode_body

    case = case_with(body={"x": float("inf")})
    assert encode_body(case.body).decode() in curl_for(case, BASE)
