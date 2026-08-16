"""Transport-failure confirmation: grouping, sampling, and verdict inheritance.

Confirming every suspect individually was the campaign's worst cost. One run
produced 120 timeouts that clustered into 5 issues — 120 replays, each burning
the full --timeout, to establish 5 facts. Sampling per group fixes that, but
only if the verdict propagates correctly, which is what these pin down.
"""

import random

import pytest

from autoqa.campaign import MAX_CONFIRMATIONS_PER_GROUP, Campaign, CampaignConfig
from autoqa.fuzz.engine import CaseBuilder
from autoqa.runner.executor import Result
from autoqa.spec.parser import Operation

OP_A = Operation(operation_id="a", method="GET", path="/a")
OP_B = Operation(operation_id="b", method="GET", path="/b")


def result_for(operation, *, error=None, status=None) -> Result:
    case = CaseBuilder(operation, random.Random(1)).baseline()
    return Result(case=case, status=status, transport_error=error, body_text="")


class FakeExecutor:
    """Stands in for the live replay, returning scripted verdicts."""

    def __init__(self, verdict_by_path: dict[str, Result]):
        self.verdicts = verdict_by_path
        self.calls = 0

    def __call__(self, *args, **kwargs):
        return self

    async def run(self, cases):
        cases = list(cases)
        self.calls += len(cases)
        return [self.verdicts[c.operation.path] for c in cases]

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None


@pytest.fixture
def campaign():
    return Campaign(CampaignConfig(spec_path="x", base_url="http://t", timeout=1.0))


async def confirm(campaign, results, verdicts, monkeypatch):
    fake = FakeExecutor(verdicts)
    monkeypatch.setattr("autoqa.campaign.Executor", fake)
    out = await campaign._confirm_transport_failures(results)
    return out, fake


async def test_only_samples_a_few_per_group(campaign, monkeypatch):
    """20 identical timeouts must not cost 20 replays."""
    results = [result_for(OP_A, error="timeout") for _ in range(20)]
    _, fake = await confirm(
        campaign, results, {"/a": result_for(OP_A, error="timeout")}, monkeypatch
    )
    assert fake.calls == MAX_CONFIRMATIONS_PER_GROUP


async def test_separate_operations_are_separate_groups(campaign, monkeypatch):
    results = [result_for(OP_A, error="timeout"), result_for(OP_B, error="timeout")]
    _, fake = await confirm(
        campaign, results,
        {"/a": result_for(OP_A, error="timeout"), "/b": result_for(OP_B, error="timeout")},
        monkeypatch,
    )
    # One per group, since each group has only one member.
    assert fake.calls == 2


async def test_different_error_classes_are_separate_groups(campaign, monkeypatch):
    results = [result_for(OP_A, error="timeout"), result_for(OP_A, error="ReadError")]
    _, fake = await confirm(
        campaign, results, {"/a": result_for(OP_A, error="timeout")}, monkeypatch
    )
    assert fake.calls == 2


async def test_confirmed_group_keeps_all_its_members(campaign, monkeypatch):
    """The sample still failed, so the input class genuinely fails."""
    results = [result_for(OP_A, error="timeout") for _ in range(10)]
    out, _ = await confirm(
        campaign, results, {"/a": result_for(OP_A, error="timeout")}, monkeypatch
    )
    assert all(r.transport_error for r in out)


async def test_unconfirmed_group_drops_all_its_members(campaign, monkeypatch):
    """The load-bearing case: an unsampled sibling must not survive on the
    strength of an original we now believe was collateral."""
    results = [result_for(OP_A, error="timeout") for _ in range(10)]
    out, _ = await confirm(
        campaign, results, {"/a": result_for(OP_A, status=200)}, monkeypatch
    )
    assert not any(r.transport_error for r in out), (
        "an unconfirmed group left members reported as transport failures"
    )
    assert all(r.status == 200 for r in out)


async def test_invalid_url_is_never_replayed(campaign, monkeypatch):
    """httpx refused to send it, so it is a fact about the input already."""
    results = [result_for(OP_A, error="InvalidURL: too long")]
    out, fake = await confirm(campaign, results, {}, monkeypatch)
    assert fake.calls == 0
    assert out[0].transport_error.startswith("InvalidURL")


async def test_clean_results_are_untouched(campaign, monkeypatch):
    results = [result_for(OP_A, status=500), result_for(OP_B, status=200)]
    out, fake = await confirm(campaign, results, {}, monkeypatch)
    assert fake.calls == 0
    assert [r.status for r in out] == [500, 200]


async def test_result_order_is_preserved(campaign, monkeypatch):
    """Positions must survive the merge back, or findings attach to the wrong case."""
    results = [
        result_for(OP_A, status=200),
        result_for(OP_B, error="timeout"),
        result_for(OP_A, status=500),
    ]
    out, _ = await confirm(
        campaign, results, {"/b": result_for(OP_B, error="timeout")}, monkeypatch
    )
    assert len(out) == 3
    assert out[0].status == 200
    assert out[2].status == 500
    assert out[1].transport_error
