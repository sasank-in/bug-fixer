"""End-to-end test: fuzz the deliberately buggy demo API and assert we find
the planted defects. This is the test that proves the whole pipeline works.
"""

import json
import socket
import sys
from pathlib import Path

import pytest

from autoqa.campaign import Campaign, CampaignConfig

pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")

ROOT = Path(__file__).resolve().parents[1]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def spec_path(tmp_path_factory) -> str:
    sys.path.insert(0, str(ROOT))
    from examples.vulnerable_api.app import app

    path = tmp_path_factory.mktemp("spec") / "openapi.json"
    path.write_text(json.dumps(app.openapi()), encoding="utf-8")
    return str(path)


@pytest.fixture(scope="module")
def report(spec_path):
    port = free_port()
    config = CampaignConfig(
        spec_path=spec_path,
        base_url=f"http://127.0.0.1:{port}",
        cases_per_operation=12,
        seed=42,
        concurrency=4,
        timeout=6.0,
        launch_command=(
            f"{sys.executable} -m uvicorn examples.vulnerable_api.app:app "
            f"--port {port} --log-level warning"
        ),
        launch_cwd=str(ROOT),
        health_path="/health",
        minimize_findings=True,
    )
    return Campaign(config).run()


def test_campaign_sends_requests(report):
    assert report.total_requests > 50


def test_target_survives_the_run(report):
    # The demo app has bugs but none should kill the process outright.
    assert not report.target_died


def test_finds_the_planted_bugs(report):
    assert len(report.clusters) >= 5, "expected multiple distinct defects"


def test_captures_server_side_stack_traces(report):
    assert report.traces, "no stack traces captured from target stderr"


def test_attaches_a_trace_to_at_least_one_cluster(report):
    # Trace correlation is the feature that turns "a 500 happened" into
    # "here is the exact line that raised".
    assert any(c.trace is not None for c in report.clusters)


def test_identifies_a_culprit_frame_in_app_code(report):
    """At least one trace must point at the demo app, not a dependency."""
    culprits = [
        c.trace.culprit.file
        for c in report.clusters
        if c.trace and c.trace.culprit
    ]
    assert culprits, "no culprit frame identified in any cluster"
    assert any("app.py" in f for f in culprits), culprits


def test_never_blames_a_library_frame(report):
    """A culprit inside site-packages would send someone to the wrong file."""
    for cluster in report.clusters:
        if cluster.trace and cluster.trace.culprit:
            assert not cluster.trace.culprit.is_library, cluster.trace.culprit.file


def test_each_cluster_covers_exactly_one_operation(report):
    """Cross-operation merging produces reports whose title and reproducer
    disagree, which is worse than not clustering at all."""
    for cluster in report.clusters:
        assert len(cluster.operations) == 1, (
            f"{cluster.title!r} merged {cluster.operations}"
        )


def test_cluster_title_and_reproducer_agree(report):
    from autoqa.report.render import curl_for

    for cluster in report.clusters:
        case = report.minimized.get(cluster.signature) or cluster.exemplar.result.case
        # The path in the reproducer must belong to the operation named in the
        # title, allowing for filled-in path placeholders.
        assert case.operation.key == cluster.exemplar.operation_key
        assert case.method in curl_for(case, report.config.base_url)


def test_traces_attach_to_the_operation_that_produced_them(report):
    """A trace whose culprit function names a different handler than the
    cluster's operation is a mis-attribution."""
    for cluster in report.clusters:
        if not (cluster.trace and cluster.trace.culprit):
            continue
        func = cluster.trace.culprit.function.lower()
        path = cluster.operations[0].split(" ", 1)[1].lower()
        if func in {"get_user", "transfer", "create_order", "search", "render", "read_file"}:
            # Handler names in the demo app map onto their route names.
            stem = {
                "get_user": "users",
                "transfer": "transfer",
                "create_order": "orders",
                "search": "search",
                "render": "render",
                "read_file": "files",
            }[func]
            assert stem in path, f"{func} attributed to {path}"


def test_clustering_actually_deduplicates(report):
    # Many raw findings must collapse into far fewer distinct issues.
    assert len(report.findings) > len(report.clusters)


def test_reports_are_renderable(report):
    from autoqa.report.render import render_json, render_markdown, render_terminal

    assert "AutoQA campaign report" in render_terminal(report)
    assert "# AutoQA Report" in render_markdown(report)
    payload = json.loads(render_json(report))
    assert payload["clusters"]
    assert all(c["reproducer"]["curl"].startswith("curl") for c in payload["clusters"])


def test_minimized_reproducers_still_reproduce(report):
    """A minimized repro that no longer triggers the bug is worse than none."""
    assert report.minimized, "nothing was minimized"
    for signature, case in report.minimized.items():
        cluster = next(c for c in report.clusters if c.signature == signature)
        original = cluster.exemplar.result
        # The minimizer only accepts candidates that still match the original
        # failure, so a minimized case must never be an empty-ish request that
        # dropped the very input under test.
        if original.status is not None and original.status >= 500:
            has_input = bool(case.query or case.body or "{" not in case.operation.path)
            assert has_input or case.path != case.operation.path, (
                f"minimized repro for {signature} dropped all input: {case}"
            )


def test_transport_failures_are_reported_unshrunk(report):
    """They can't be verified after shrinking, so the full request is kept."""
    for cluster in report.clusters:
        if cluster.exemplar.result.transport_error:
            assert cluster.signature not in report.minimized


def test_no_empty_transport_error_messages(report):
    for result in report.results:
        if result.transport_error:
            assert not result.transport_error.rstrip().endswith(":")


def test_seed_makes_runs_reproducible(spec_path):
    from autoqa.fuzz.engine import build_cases
    from autoqa.spec.parser import OpenAPISpec

    ops = OpenAPISpec.from_file(spec_path).operations()
    first = [c.label for c in build_cases(ops, 8, seed=2024)]
    second = [c.label for c in build_cases(ops, 8, seed=2024)]
    assert first == second
