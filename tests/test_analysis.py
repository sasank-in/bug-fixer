import random

from autoqa.analysis.cluster import cluster_findings, normalize
from autoqa.analysis.minimizer import minimize, same_failure
from autoqa.analysis.oracles import Severity, evaluate
from autoqa.analysis.traces import extract_traces
from autoqa.fuzz.engine import CaseBuilder
from autoqa.fuzz.mutators import Mutation
from autoqa.runner.executor import Result
from autoqa.runner.process import LogLine
from autoqa.spec.parser import Operation

OP = Operation(operation_id="op", method="GET", path="/x")


def make_result(**kwargs) -> Result:
    case = CaseBuilder(OP, random.Random(1)).baseline()
    case.is_baseline = kwargs.pop("is_baseline", False)
    case.mutations = kwargs.pop("mutations", [])
    return Result(case=case, **kwargs)


# -- oracles ---------------------------------------------------------------


def test_500_is_a_finding():
    findings = evaluate([make_result(status=500)])
    assert any(f.kind == "server_error" for f in findings)


def test_400_is_not_a_finding():
    # Rejecting bad input is correct behaviour, not a bug.
    assert evaluate([make_result(status=400)]) == []


def test_200_is_not_a_finding():
    assert evaluate([make_result(status=200)]) == []


def test_baseline_failure_is_its_own_kind():
    findings = evaluate([make_result(status=500, is_baseline=True)])
    assert [f.kind for f in findings] == ["baseline_failure"]
    assert findings[0].severity is Severity.CRITICAL


def test_timeout_is_a_finding():
    findings = evaluate([make_result(transport_error="timeout")])
    assert any(f.kind == "hang" for f in findings)


def test_connection_failure_is_critical():
    findings = evaluate([make_result(transport_error="ConnectError: refused")])
    assert findings[0].severity is Severity.CRITICAL


def test_leaked_traceback_is_detected():
    body = 'Traceback (most recent call last):\n  File "app.py", line 1, in f'
    findings = evaluate([make_result(status=500, body_text=body)])
    assert any(f.kind == "leak_python_traceback" for f in findings)


def test_leaked_sql_error_is_critical():
    findings = evaluate([make_result(status=500, body_text="near \"x\": syntax error at or near foo")])
    leaks = [f for f in findings if f.kind == "leak_sql_error"]
    assert leaks and leaks[0].severity is Severity.CRITICAL


def test_clean_error_body_is_not_a_leak():
    findings = evaluate([make_result(status=400, body_text='{"error":"invalid input"}')])
    assert findings == []


def test_template_injection_detected_when_evaluated():
    result = make_result(
        status=200,
        body_text="49",
        mutations=[Mutation("hostile_string", "?t", "{{7*7}}")],
    )
    findings = evaluate([result])
    assert any(f.kind == "template_injection" for f in findings)


def test_template_injection_not_flagged_when_only_echoed():
    # The payload is reflected verbatim; 49 never appears, so it wasn't evaluated.
    result = make_result(
        status=200,
        body_text="{{7*7}}",
        mutations=[Mutation("hostile_string", "?t", "{{7*7}}")],
    )
    assert not any(f.kind == "template_injection" for f in evaluate([result]))


def test_accepting_dropped_required_field_is_flagged():
    result = make_result(
        status=200, mutations=[Mutation("drop_required", "name", "<removed>")]
    )
    assert any(f.kind == "missing_validation" for f in evaluate([result]))


def test_latency_outlier_needs_a_sample():
    # Two slow results alone must not trigger an outlier finding.
    results = [make_result(status=200, elapsed_ms=5000) for _ in range(2)]
    assert not any(f.kind == "latency_outlier" for f in evaluate(results))


def test_latency_outlier_detected_against_baseline():
    results = [make_result(status=200, elapsed_ms=10) for _ in range(12)]
    results.append(make_result(status=200, elapsed_ms=9000))
    assert any(f.kind == "latency_outlier" for f in evaluate(results))


# -- clustering ------------------------------------------------------------


def test_normalize_strips_volatile_data():
    a = normalize("failed for id 550e8400-e29b-41d4-a716-446655440000 at line 42")
    b = normalize("failed for id 660e8400-e29b-41d4-a716-446655440001 at line 99")
    assert a == b


def test_normalize_strips_the_offending_value():
    # The fuzzer sends a different value each time; the defect is identical.
    a = normalize("[Errno 2] No such file or directory: 'readme.txt'")
    b = normalize("[Errno 2] No such file or directory: '../../etc/passwd'")
    assert a == b


def test_normalize_keeps_genuinely_different_errors_apart():
    a = normalize("[Errno 2] No such file or directory: 'x'")
    b = normalize("[Errno 13] Permission denied: 'x'")
    assert a != b


def test_same_defect_with_different_payloads_is_one_cluster():
    """The regression this guards: one bug reported five times."""
    bodies = [
        '{"error":"[Errno 2] No such file or directory: \'readme.txt\'"}',
        '{"error":"[Errno 2] No such file or directory: \'-1\'"}',
        '{"error":"[Errno 2] No such file or directory: \'0.0\'"}',
        '{"error":"[Errno 2] No such file or directory: \'oFyOI\'"}',
        "{\"error\":\"[Errno 2] No such file or directory: \\\"' OR '1'='1\\\"\"}",
    ]
    findings = evaluate([make_result(status=500, body_text=b) for b in bodies])
    server_errors = [f for f in findings if f.kind == "server_error"]
    assert len(cluster_findings(server_errors)) == 1


def test_identical_errors_collapse_to_one_cluster():
    findings = evaluate([make_result(status=500, body_text="boom") for _ in range(10)])
    clusters = cluster_findings(findings)
    assert len(clusters) == 1
    assert clusters[0].count == 10


def test_different_errors_stay_separate():
    findings = evaluate(
        [
            make_result(status=500, body_text="database is locked"),
            make_result(status=500, body_text="cannot divide by zero"),
        ]
    )
    assert len(cluster_findings(findings)) == 2


def test_clusters_sort_worst_first():
    findings = evaluate(
        [
            make_result(status=500, body_text="plain"),
            make_result(transport_error="ConnectError: refused"),
        ]
    )
    clusters = cluster_findings(findings)
    assert clusters[0].severity is Severity.CRITICAL


def test_trace_correlates_by_time_window():
    log = 'Traceback (most recent call last):\n  File "/app/a.py", line 3, in f\nValueError: bad\n'
    traces = extract_traces(
        [LogLine(1000.0 + i, "stderr", t) for i, t in enumerate(log.splitlines())]
    )
    # Body says nothing useful; only the timing links request to trace.
    result = make_result(
        status=500, body_text="Internal Server Error", sent_at=999.0, received_at=1003.0
    )
    clusters = cluster_findings(evaluate([result]), traces)
    assert clusters[0].trace is not None
    assert clusters[0].trace.exception_type == "ValueError"


def test_transport_failure_never_adopts_a_trace():
    """A timeout produced no response, so any overlapping trace is another
    request's. Attributing it would blame the wrong endpoint."""
    log = 'Traceback (most recent call last):\n  File "/app/a.py", line 3, in f\nValueError: bad\n'
    traces = extract_traces(
        [LogLine(1000.0 + i, "stderr", t) for i, t in enumerate(log.splitlines())]
    )
    result = make_result(transport_error="timeout", sent_at=999.0, received_at=1003.0)
    assert cluster_findings(evaluate([result]), traces)[0].trace is None


def test_one_trace_does_not_merge_different_operations():
    """A shared helper raising the same error on two endpoints must stay two
    clusters — otherwise the title names one endpoint and the repro hits another."""
    op_a = Operation(operation_id="a", method="GET", path="/alpha")
    op_b = Operation(operation_id="b", method="POST", path="/beta")

    findings = []
    for op in (op_a, op_b):
        case = CaseBuilder(op, random.Random(1)).baseline()
        case.is_baseline = False
        findings.extend(
            evaluate([Result(case=case, status=500, body_text="shared helper blew up")])
        )

    clusters = cluster_findings(findings)
    assert len(clusters) == 2
    assert {c.operations[0] for c in clusters} == {"GET /alpha", "POST /beta"}


def test_cluster_title_matches_its_exemplar():
    """The headline and the reproducer must describe the same finding."""
    results = [
        make_result(status=500, body_text="boom", mutations=[Mutation("t", "x", "y")]),
        make_result(status=500, body_text="boom", is_baseline=True),
    ]
    for cluster in cluster_findings(evaluate(results)):
        assert cluster.title == cluster.exemplar.title
        assert cluster.detail == cluster.exemplar.detail
        assert cluster.severity is cluster.exemplar.severity


def test_trace_not_attached_when_window_is_ambiguous():
    log = (
        'Traceback (most recent call last):\n  File "/app/a.py", line 3, in f\nValueError: bad\n'
        'Traceback (most recent call last):\n  File "/app/b.py", line 9, in g\nKeyError: other\n'
    )
    traces = extract_traces(
        [LogLine(1000.0 + i, "stderr", t) for i, t in enumerate(log.splitlines())]
    )
    result = make_result(
        status=500, body_text="Internal Server Error", sent_at=999.0, received_at=1010.0
    )
    # Two different exception types overlap this request; guessing would be wrong.
    assert cluster_findings(evaluate([result]), traces)[0].trace is None


# -- minimizer -------------------------------------------------------------


def test_same_failure_requires_matching_body_shape():
    original = make_result(status=500, body_text="No such file: 'a.txt'")
    matches = same_failure(original)
    # Same error, different filename -> same failure.
    assert matches(make_result(status=500, body_text="No such file: 'b.txt'"))
    # Same status, entirely different error -> not the same failure.
    assert not matches(make_result(status=500, body_text="division by zero"))


def test_same_failure_rejects_different_status():
    matches = same_failure(make_result(status=500, body_text="boom"))
    assert not matches(make_result(status=404, body_text="boom"))


async def test_minimize_shrinks_payload_to_the_culprit():
    case = CaseBuilder(OP, random.Random(3)).baseline()
    case.body = {"keep": -1, "noise_a": "x" * 500, "noise_b": [1, 2, 3], "noise_c": True}
    case.query = {"unused": "junk"}

    async def still_fails(candidate) -> bool:
        # Only the negative `keep` value actually triggers the bug.
        return isinstance(candidate.body, dict) and candidate.body.get("keep") == -1

    result = await minimize(case, still_fails)
    assert result.body == {"keep": -1}
    assert result.query == {}


def test_transport_failures_are_not_minimizable():
    """Shrinking them yields repros that don't reproduce; skip instead."""
    from autoqa.analysis.minimizer import is_minimizable

    assert not is_minimizable(make_result(transport_error="ReadError"))
    assert not is_minimizable(make_result(transport_error="timeout"))
    assert is_minimizable(make_result(status=500, body_text="boom"))


async def test_minimize_keeps_case_when_nothing_can_be_removed():
    case = CaseBuilder(OP, random.Random(4)).baseline()
    case.body = {"a": 1}
    case.query = {}
    case.headers = {}

    async def still_fails(candidate) -> bool:
        return candidate.body == {"a": 1}

    assert (await minimize(case, still_fails)).body == {"a": 1}
