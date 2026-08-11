"""End-to-end test: fuzz the deliberately buggy demo API and assert we find
the planted defects. This is the test that proves the whole pipeline works.
"""

import json
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from autoqa.campaign import Campaign, CampaignConfig
from autoqa.report.render import request_url
from autoqa.runner.http import encode_body, with_default_content_type

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


def test_reported_reproducers_actually_reproduce(spec_path):
    """Replay every reported reproducer and require the claimed outcome.

    The load-bearing test for the whole tool: a report whose curl lines do not
    reproduce is worthless, and structural checks alone missed exactly that —
    exemplar selection once picked whichever cluster member had the smallest
    body, which was often not a request that failed at all.
    """
    import httpx

    port = free_port()
    config = CampaignConfig(
        spec_path=spec_path,
        base_url=f"http://127.0.0.1:{port}",
        cases_per_operation=10,
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
    report = Campaign(config).run()
    assert report.clusters

    # The campaign stops its target on the way out, so bring up a fresh one to
    # replay against.
    replay_port = free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "examples.vulnerable_api.app:app",
         "--port", str(replay_port), "--log-level", "error"],
        cwd=str(ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{replay_port}"
    try:
        for _ in range(75):
            try:
                if httpx.get(f"{base}/health", timeout=2).status_code == 200:
                    break
            except Exception:
                time.sleep(0.4)
        else:
            pytest.skip("replay target never became ready")

        mismatches = []
        for cluster in report.clusters:
            case = report.minimized.get(cluster.signature) or cluster.exemplar.result.case
            claimed = cluster.exemplar.result
            url = request_url(case, base)
            # Replay exactly as the executor sent it — including the default
            # content-type, without which FastAPI rejects the body as 422 and
            # the replay measures the test's mistake instead of the tool's.
            headers = dict(case.headers)
            content = None
            if case.body is not None:
                headers = with_default_content_type(headers)
                content = encode_body(case.body)
            try:
                resp = httpx.request(
                    case.method, url,
                    headers=headers or None,
                    content=content,
                    timeout=10,
                )
                got, err = resp.status_code, None
            except Exception as exc:
                got, err = None, type(exc).__name__

            # A reported transport failure has already been confirmed serially
            # during the campaign, so it must fail at the transport level again;
            # anything else is compared on status.
            reproduced = (
                err is not None if claimed.transport_error else got == claimed.status
            )

            if not reproduced:
                mismatches.append(
                    f"{cluster.title!r}: claimed "
                    f"{claimed.status or claimed.transport_error}, replay gave {got or err}"
                )

        assert not mismatches, "reproducers did not reproduce:\n  " + "\n  ".join(mismatches)
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def test_mutation_tags_describe_the_reported_reproducer(report):
    """Tags aggregated across a cluster describe requests the reader never sees."""
    for cluster in report.clusters:
        exemplar_tags = {m.tag for m in cluster.exemplar.result.case.mutations}
        assert set(cluster.mutation_tags) == exemplar_tags, (
            f"{cluster.title!r} lists {cluster.mutation_tags} but its reproducer "
            f"applied {sorted(exemplar_tags)}"
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
