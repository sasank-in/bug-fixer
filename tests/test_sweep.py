"""Deterministic security sweep, and the injection oracle it feeds.

The sweep exists because random sampling made injection detection a lottery:
a specific payload reached a given parameter ~37% of the time at --cases 20.
These tests pin the guarantee (every payload reaches every target, every run)
and — more importantly — pin the false-positive guards, since a security oracle
that cries wolf is worse than none.
"""

import random

import pytest

from autoqa.analysis.oracles import Severity, evaluate
from autoqa.fuzz.engine import CaseBuilder
from autoqa.fuzz.mutators import Mutation
from autoqa.fuzz.sweep import (
    SECURITY_PAYLOADS,
    build_sweep_cases,
    estimate,
    targets_for,
)
from autoqa.runner.executor import Result
from autoqa.spec.parser import Operation, Parameter

STR_SCHEMA = {"type": "string"}
INT_SCHEMA = {"type": "integer"}


def op_with(**kwargs) -> Operation:
    base = {"operation_id": "op", "method": "GET", "path": "/x"}
    base.update(kwargs)
    return Operation(**base)


# -- target discovery ------------------------------------------------------


def test_finds_string_query_params():
    op = op_with(parameters=(Parameter("q", "query", True, STR_SCHEMA),))
    assert [t.name for t in targets_for(op)] == ["q"]


def test_skips_integer_params():
    """Injecting a string into an int field just trips type validation."""
    op = op_with(parameters=(Parameter("limit", "query", False, INT_SCHEMA),))
    assert targets_for(op) == []


def test_untyped_params_are_probed():
    # No declared type means it could be anything, so it is worth a probe.
    op = op_with(parameters=(Parameter("x", "query", False, {}),))
    assert len(targets_for(op)) == 1


def test_finds_path_and_header_targets():
    op = op_with(
        path="/u/{id}",
        parameters=(
            Parameter("id", "path", True, STR_SCHEMA),
            Parameter("X-Tok", "header", False, STR_SCHEMA),
        ),
    )
    assert {t.kind for t in targets_for(op)} == {"path", "header"}


def test_finds_string_body_properties():
    op = op_with(
        method="POST",
        body_schema={
            "type": "object",
            "properties": {"name": STR_SCHEMA, "count": INT_SCHEMA},
        },
    )
    assert [t.name for t in targets_for(op) if t.kind == "body"] == ["name"]


def test_freeform_object_body_gets_probed():
    """A schema with no properties still has handlers reading keys out of it."""
    op = op_with(method="POST", body_schema={"type": "object"})
    assert [t.kind for t in targets_for(op)] and all(
        t.kind == "body" for t in targets_for(op)
    )


# -- the coverage guarantee ------------------------------------------------


def test_every_payload_reaches_every_target():
    op = op_with(
        parameters=(
            Parameter("a", "query", True, STR_SCHEMA),
            Parameter("b", "query", False, STR_SCHEMA),
        )
    )
    cases = list(build_sweep_cases([op], seed=1))
    sent = {(c.mutations[0].target, c.mutations[0].tag) for c in cases}
    expected = {
        (t.label(), p.tag) for t in targets_for(op) for p in SECURITY_PAYLOADS
    }
    assert sent == expected


def test_coverage_is_identical_regardless_of_seed():
    """The whole point: no seed can make a payload go unsent."""
    op = op_with(parameters=(Parameter("q", "query", True, STR_SCHEMA),))
    tags = [
        sorted(c.mutations[0].tag for c in build_sweep_cases([op], seed=s))
        for s in (1, 2, 999)
    ]
    assert tags[0] == tags[1] == tags[2]
    assert len(tags[0]) == len(SECURITY_PAYLOADS)


def test_estimate_matches_what_is_generated():
    op = op_with(
        parameters=(
            Parameter("a", "query", True, STR_SCHEMA),
            Parameter("b", "header", False, STR_SCHEMA),
        )
    )
    assert estimate([op]) == len(list(build_sweep_cases([op], seed=1)))


def test_operations_with_no_string_targets_are_skipped():
    op = op_with(parameters=(Parameter("n", "query", True, INT_SCHEMA),))
    assert list(build_sweep_cases([op], seed=1)) == []


def test_each_case_carries_exactly_one_mutation():
    """Single-mutation discipline: blame must stay unambiguous."""
    op = op_with(parameters=(Parameter("q", "query", True, STR_SCHEMA),))
    for case in build_sweep_cases([op], seed=1):
        assert len(case.mutations) == 1
        assert not case.is_baseline


def test_path_payloads_leave_no_unfilled_placeholder():
    op = op_with(path="/u/{id}/p/{pid}",
                 parameters=(Parameter("id", "path", True, STR_SCHEMA),
                             Parameter("pid", "path", True, STR_SCHEMA)))
    for case in build_sweep_cases([op], seed=1):
        assert "{" not in case.path


def test_header_payloads_have_crlf_stripped():
    """CR/LF would break the client before reaching the target."""
    op = op_with(parameters=(Parameter("X-T", "header", True, STR_SCHEMA),))
    for case in build_sweep_cases([op], seed=1):
        for value in case.headers.values():
            assert "\r" not in value and "\n" not in value


# -- the oracle: true positives --------------------------------------------


def make_result(body: str, mutation: Mutation) -> Result:
    case = CaseBuilder(op_with(), random.Random(1)).baseline()
    case.is_baseline = False
    case.mutations = [mutation]
    return Result(case=case, status=200, body_text=body)


def test_detects_evaluated_template():
    r = make_result("The answer is 49", Mutation("template_injection", "?q", "{{7*7}}"))
    findings = evaluate([r])
    assert any(f.kind == "template_injection" for f in findings)
    assert findings[0].severity is Severity.CRITICAL


def test_detects_unix_path_traversal():
    r = make_result(
        "root:x:0:0:root:/root:/bin/bash",
        Mutation("traversal_unix", "?f", "../../../../etc/passwd"),
    )
    assert any(f.kind == "path_traversal" for f in evaluate([r]))


def test_detects_windows_path_traversal():
    r = make_result(
        "[fonts]\r\n[extensions]",
        Mutation("traversal_win", "?f", "..\\..\\..\\windows\\win.ini"),
    )
    assert any(f.kind == "path_traversal_win" for f in evaluate([r]))


# -- the oracle: false-positive guards -------------------------------------
# These are the load-bearing tests. Each one is a real false positive the
# first version of this oracle produced against the demo API.


def test_echoed_template_is_not_an_injection():
    """Reflecting the payload verbatim is correct behaviour."""
    r = make_result(
        '{"match":"{{7*7}}"}', Mutation("template_injection", "?q", "{{7*7}}")
    )
    assert not any(f.kind == "template_injection" for f in evaluate([r]))


def test_49_inside_a_longer_number_is_not_an_injection():
    """Regression: '49' matched inside '324286.6249' on POST /orders."""
    r = make_result(
        '{"total":324286.6249,"item":"x"}',
        Mutation("expression_injection", "$body.item", "${7*7}"),
    )
    assert not any(f.kind == "expression_injection" for f in evaluate([r]))


@pytest.mark.parametrize(
    "body", ['{"n":1490}', '{"n":49.5}', '{"n":0.49}', '{"v":"a49b"}']
)
def test_embedded_49_never_counts_as_evaluation(body):
    r = make_result(body, Mutation("template_injection", "?q", "{{7*7}}"))
    assert not any(f.kind == "template_injection" for f in evaluate([r]))


def test_standalone_49_does_count():
    r = make_result('{"result": 49}', Mutation("template_injection", "?q", "{{7*7}}"))
    assert any(f.kind == "template_injection" for f in evaluate([r]))


def test_payload_never_sent_means_no_finding():
    """A marker in the body proves nothing if we never sent the trigger."""
    r = make_result("root:x:0:0", Mutation("hostile_string", "?q", "harmless"))
    assert not any(f.kind == "path_traversal" for f in evaluate([r]))


def test_baseline_requests_are_never_injection_findings():
    case = CaseBuilder(op_with(), random.Random(1)).baseline()
    r = Result(case=case, status=200, body_text="49 root:x:0:0")
    assert not any("injection" in f.kind for f in evaluate([r]))
