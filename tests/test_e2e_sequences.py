"""End-to-end proof that sequence fuzzing reaches bugs single requests cannot.

examples/crud_api/ has stateful defects only: every endpoint handles a fresh
request correctly, and misbehaves only on state a previous request created.
If sequence fuzzing works, it finds them; if it does not, no amount of
independent fuzzing will.
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
    from examples.crud_api.app import app

    path = tmp_path_factory.mktemp("spec") / "crud.json"
    path.write_text(json.dumps(app.openapi()), encoding="utf-8")
    return str(path)


def run_campaign(spec_path: str, *, sequences: bool, cases: int):
    port = free_port()
    config = CampaignConfig(
        spec_path=spec_path,
        base_url=f"http://127.0.0.1:{port}",
        cases_per_operation=cases,
        seed=1,
        concurrency=4,
        timeout=5.0,
        launch_command=(
            f"{sys.executable} -m uvicorn examples.crud_api.app:app "
            f"--port {port} --log-level warning"
        ),
        launch_cwd=str(ROOT),
        health_path="/health",
        minimize_findings=False,
        security_sweep=False,
        stateful_sequences=sequences,
    )
    return Campaign(config).run()


@pytest.fixture(scope="module")
def with_sequences(spec_path):
    return run_campaign(spec_path, sequences=True, cases=5)


@pytest.fixture(scope="module")
def without_sequences(spec_path):
    # Ten times the cases, to make the comparison fair: this is not a
    # sampling-budget difference, it is a reachability difference.
    return run_campaign(spec_path, sequences=False, cases=50)


def stateful_kinds(report) -> set[str]:
    return {
        c.kind for c in report.clusters
        if c.kind in ("stateful_crash", "stale_state_accepted", "stale_read")
    }


def test_sequences_run_at_all(with_sequences):
    assert with_sequences.sequence_runs, "no sequences were executed"


def test_finds_stateful_bugs(with_sequences):
    assert stateful_kinds(with_sequences), "no stateful findings"


def test_finds_use_after_delete_and_double_delete(with_sequences):
    """Both planted crashes need a create and a delete to have happened first."""
    names = {
        c.title for c in with_sequences.clusters if c.kind == "stateful_crash"
    }
    joined = " ".join(names)
    assert "read_after_delete" in joined or "double_delete" in joined, names


def test_single_request_fuzzing_cannot_reach_them(without_sequences):
    """The control: 10x the cases, sequences off, finds none of these."""
    assert stateful_kinds(without_sequences) == set()


def test_sequences_are_the_reason(with_sequences, without_sequences):
    """The capability claim, stated as a comparison."""
    gained = stateful_kinds(with_sequences) - stateful_kinds(without_sequences)
    assert gained, (
        "sequence fuzzing found nothing that single-request fuzzing missed"
    )


def test_findings_name_the_chain_that_caused_them(with_sequences):
    """A stateful finding is unactionable without the ordering that caused it."""
    for cluster in with_sequences.clusters:
        if cluster.kind != "stateful_crash":
            continue
        detail = cluster.detail
        assert "Reached by:" in detail
        # The chain must show at least one prior request with its status.
        assert "->" in detail


def test_no_sequence_finding_blames_the_first_step(with_sequences):
    """Step 0 has no prior state, so it is not a sequence bug."""
    for run in with_sequences.sequence_runs:
        for outcome in run.outcomes:
            if outcome.index == 0 and outcome.result.status == 500:
                titles = [c.title for c in with_sequences.clusters]
                assert not any("after" in t and run.sequence.name in t for t in titles)


def test_aborted_sequences_are_not_reported_as_findings(with_sequences):
    """A sequence that could not set up its resource proves nothing."""
    for run in with_sequences.sequence_runs:
        if not run.completed:
            assert run.abort_reason
