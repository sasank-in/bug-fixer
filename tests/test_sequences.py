"""Stateful sequence fuzzing: resource discovery, chaining, and oracles.

The capability these unlock: use-after-delete, double-delete, and
non-idempotent transitions are invisible to independent requests no matter how
many you send. The e2e test proves that directly.
"""

import random

import pytest

from autoqa.analysis.oracles import Severity
from autoqa.analysis.sequence_oracles import evaluate_sequence
from autoqa.fuzz.engine import CaseBuilder
from autoqa.fuzz.sequences import (
    Sequence,
    Step,
    build_sequences,
    discover_resources,
    extract_id,
    realise_step,
)
from autoqa.runner.executor import Result
from autoqa.runner.sequence_runner import SequenceRun, StepOutcome
from autoqa.spec.parser import Operation, Parameter

ID_PARAM = Parameter("note_id", "path", True, {"type": "integer"})


def op(method: str, path: str, **kw) -> Operation:
    params = (ID_PARAM,) if "{note_id}" in path else ()
    return Operation(
        operation_id=kw.pop("operation_id", f"{method}_{path}"),
        method=method, path=path, parameters=params, **kw
    )


CREATE = op("POST", "/notes", body_schema={"type": "object",
                                           "properties": {"title": {"type": "string"}}})
READ = op("GET", "/notes/{note_id}")
UPDATE = op("PUT", "/notes/{note_id}")
DELETE = op("DELETE", "/notes/{note_id}")
LIST = op("GET", "/notes")
PUBLISH = op("POST", "/notes/{note_id}/publish")


# -- resource discovery ----------------------------------------------------


def test_groups_crud_operations_into_one_resource():
    resources = discover_resources([CREATE, READ, UPDATE, DELETE, LIST])
    assert len(resources) == 1
    r = resources[0]
    assert r.collection == "/notes"
    assert (r.create, r.read, r.update, r.delete) == (CREATE, READ, UPDATE, DELETE)


def test_sub_path_actions_fold_into_the_parent_resource():
    """/notes/{id}/publish belongs to /notes, not its own resource."""
    resources = discover_resources([CREATE, DELETE, PUBLISH])
    assert len(resources) == 1
    assert PUBLISH in resources[0].actions


def test_resource_without_a_create_is_not_fuzzable():
    # Nothing can be chained if there is no way to make a resource.
    assert discover_resources([READ, DELETE]) == []


def test_resource_with_only_create_is_not_fuzzable():
    assert discover_resources([CREATE]) == []


def test_unrelated_paths_stay_separate():
    other = op("POST", "/users")
    other_read = op("GET", "/users/{note_id}")
    resources = discover_resources([CREATE, READ, other, other_read])
    assert {r.collection for r in resources} == {"/notes", "/users"}


# -- sequence construction -------------------------------------------------


def sequences_for(*ops) -> dict[str, Sequence]:
    resources = discover_resources(list(ops))
    return {s.name: s for r in resources for s in build_sequences(r)}


def test_double_delete_sequence_is_built():
    seqs = sequences_for(CREATE, DELETE)
    assert "double_delete" in seqs
    steps = seqs["double_delete"].steps
    assert [s.operation.method for s in steps] == ["POST", "DELETE", "DELETE"]
    assert steps[-1].expect_failure


def test_read_after_delete_sequence_is_built():
    seqs = sequences_for(CREATE, READ, DELETE)
    steps = seqs["read_after_delete"].steps
    assert [s.operation.method for s in steps] == ["POST", "DELETE", "GET"]


def test_later_steps_depend_on_the_create_step():
    steps = sequences_for(CREATE, DELETE)["double_delete"].steps
    assert steps[0].id_from_step is None
    assert all(s.id_from_step == 0 for s in steps[1:])


def test_action_sequences_are_built_per_action():
    seqs = sequences_for(CREATE, DELETE, PUBLISH)
    assert "repeat_publish" in seqs
    assert "publish_after_delete" in seqs


def test_no_delete_means_no_delete_sequences():
    seqs = sequences_for(CREATE, READ, UPDATE)
    assert not any("delete" in name for name in seqs)


def test_every_sequence_states_a_hypothesis():
    """The report explains why the ordering mattered, so it must exist."""
    for seq in sequences_for(CREATE, READ, UPDATE, DELETE, PUBLISH).values():
        assert seq.hypothesis


# -- id extraction ---------------------------------------------------------


@pytest.mark.parametrize(
    "body,expected",
    [
        ({"id": 7}, 7),
        ({"uuid": "abc-123"}, "abc-123"),
        ({"data": {"id": 9}}, 9),          # single-key wrapper
        ({"title": "x", "id": 3}, 3),      # prefers `id` over position
        ([{"id": 5}], 5),                  # list response
        ({"nested": {"id": 11}}, 11),
    ],
)
def test_extracts_the_resource_id(body, expected):
    assert extract_id(body) == expected


@pytest.mark.parametrize(
    "body", [{}, {"title": "no id here"}, [], None, {"id": None}, {"id": True}]
)
def test_returns_none_when_no_usable_id(body):
    # A bool is not an id; substituting True into a path would be nonsense.
    assert extract_id(body) is None


def test_id_field_preference_beats_key_order():
    assert extract_id({"owner": "bob", "name": "n", "id": 42}) == 42


# -- step realisation ------------------------------------------------------


def test_id_is_substituted_into_the_path():
    step = Step(READ, id_from_step=0)
    case = realise_step(step, 42, random.Random(1))
    assert case.path == "/notes/42"


def test_id_is_url_encoded():
    step = Step(READ, id_from_step=0)
    case = realise_step(step, "a/b c", random.Random(1))
    assert "/" not in case.path.removeprefix("/notes/")


def test_step_without_dependency_keeps_generated_path():
    case = realise_step(Step(CREATE), None, random.Random(1))
    assert case.path == "/notes"


# -- oracles ---------------------------------------------------------------


def result_for(operation, status, body="") -> Result:
    case = CaseBuilder(operation, random.Random(1)).baseline()
    return Result(case=case, status=status, body_text=body)


def run_with(*outcomes, name="double_delete", hypothesis="h") -> SequenceRun:
    seq = Sequence(name, "/notes", [], hypothesis=hypothesis)
    run = SequenceRun(sequence=seq)
    run.outcomes = list(outcomes)
    return run


def test_500_after_a_successful_step_is_critical():
    run = run_with(
        StepOutcome(0, result_for(CREATE, 201), "create", False, 1),
        StepOutcome(1, result_for(DELETE, 204), "delete", False),
        StepOutcome(2, result_for(DELETE, 500), "second delete", True),
    )
    findings = evaluate_sequence(run)
    assert [f.kind for f in findings] == ["stateful_crash"]
    assert findings[0].severity is Severity.CRITICAL


def test_correct_404_on_the_repeat_is_not_a_finding():
    """Rejecting the second delete is right; it must not be reported."""
    run = run_with(
        StepOutcome(0, result_for(CREATE, 201), "create", False, 1),
        StepOutcome(1, result_for(DELETE, 204), "delete", False),
        StepOutcome(2, result_for(DELETE, 404), "second delete", True),
    )
    assert evaluate_sequence(run) == []


def test_failure_on_the_first_step_is_not_a_sequence_finding():
    """No prior state existed, so the ordinary oracles own this one."""
    run = run_with(StepOutcome(0, result_for(CREATE, 500), "create", False))
    assert evaluate_sequence(run) == []


def test_success_where_failure_was_expected_is_flagged():
    run = run_with(
        StepOutcome(0, result_for(CREATE, 201), "create", False, 1),
        StepOutcome(1, result_for(DELETE, 204), "delete", False),
        StepOutcome(2, result_for(READ, 200, '{"id":1}'), "read deleted", True),
        name="read_after_delete",
    )
    findings = evaluate_sequence(run)
    assert [f.kind for f in findings] == ["stale_state_accepted"]


def test_detail_names_the_chain_that_caused_it():
    """A sequence finding is useless without the steps that produced it."""
    run = run_with(
        StepOutcome(0, result_for(CREATE, 201), "create", False, 1),
        StepOutcome(1, result_for(DELETE, 204), "delete", False),
        StepOutcome(2, result_for(DELETE, 500), "second delete", True),
    )
    detail = evaluate_sequence(run)[0].detail
    assert "POST" in detail and "DELETE" in detail and "201" in detail


def test_stale_read_detected():
    run = run_with(
        StepOutcome(0, result_for(CREATE, 201), "", False, 1),
        StepOutcome(1, result_for(UPDATE, 200, '{"title":"new"}'), "", False),
        StepOutcome(2, result_for(READ, 200, '{"title":"old"}'), "", False),
        name="update_then_read",
    )
    assert [f.kind for f in evaluate_sequence(run)] == ["stale_read"]


def test_matching_read_after_write_is_clean():
    run = run_with(
        StepOutcome(0, result_for(CREATE, 201), "", False, 1),
        StepOutcome(1, result_for(UPDATE, 200, '{"title":"new"}'), "", False),
        StepOutcome(2, result_for(READ, 200, '{"title":"new"}'), "", False),
        name="update_then_read",
    )
    assert evaluate_sequence(run) == []


def test_server_owned_fields_do_not_count_as_stale():
    """A bumped version counter is bookkeeping, not a caching bug."""
    run = run_with(
        StepOutcome(0, result_for(CREATE, 201), "", False, 1),
        StepOutcome(1, result_for(UPDATE, 200, '{"title":"x","version":2}'), "", False),
        StepOutcome(2, result_for(READ, 200, '{"title":"x","version":3}'), "", False),
        name="update_then_read",
    )
    assert evaluate_sequence(run) == []
