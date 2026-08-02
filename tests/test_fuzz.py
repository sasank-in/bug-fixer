import random

from autoqa.fuzz import mutators
from autoqa.fuzz.engine import CaseBuilder, build_cases
from autoqa.fuzz.generators import generate
from autoqa.spec.parser import Operation, Parameter


def rng() -> random.Random:
    return random.Random(7)


def test_generate_respects_type():
    assert isinstance(generate({"type": "integer"}, rng()), int)
    assert isinstance(generate({"type": "string"}, rng()), str)
    assert isinstance(generate({"type": "boolean"}, rng()), bool)
    assert isinstance(generate({"type": "array", "items": {"type": "integer"}}, rng()), list)


def test_generate_respects_enum():
    for _ in range(20):
        assert generate({"enum": ["a", "b"]}, rng()) in ("a", "b")


def test_generate_respects_integer_bounds():
    for seed in range(50):
        value = generate({"type": "integer", "minimum": 5, "maximum": 9}, random.Random(seed))
        assert 5 <= value <= 9


def test_generate_includes_all_required_properties():
    schema = {
        "type": "object",
        "required": ["a", "b"],
        "properties": {"a": {"type": "string"}, "b": {"type": "integer"}, "c": {"type": "boolean"}},
    }
    for seed in range(25):
        out = generate(schema, random.Random(seed))
        assert "a" in out and "b" in out


def test_generate_terminates_on_recursive_schema():
    schema = {"type": "object", "properties": {}}
    schema["properties"]["self"] = schema  # direct cycle
    generate(schema, rng())  # must not hang or recurse forever


def test_uuid_format_looks_like_a_uuid():
    value = generate({"type": "string", "format": "uuid"}, rng())
    assert len(value) == 36 and value.count("-") == 4


def test_mutate_leaf_changes_exactly_one_value():
    payload = {"a": 1, "b": {"c": "x"}, "d": [1, 2]}
    result = mutators.mutate_leaf(payload, rng())
    assert result is not None
    mutated, mutation = result
    assert mutated != payload
    assert mutation.tag
    # The original must not be touched.
    assert payload == {"a": 1, "b": {"c": "x"}, "d": [1, 2]}


def test_drop_required_removes_a_field():
    result = mutators.drop_required_field({"a": 1, "b": 2}, ["a"], rng())
    assert result is not None
    payload, mutation = result
    assert "a" not in payload
    assert mutation.tag == "drop_required"


def test_drop_required_returns_none_when_absent():
    assert mutators.drop_required_field({"b": 2}, ["a"], rng()) is None


def test_inject_unknown_field_adds_a_key():
    payload, mutation = mutators.inject_unknown_field({"a": 1}, rng())
    assert len(payload) == 2
    assert mutation.tag == "unknown_field"


def sample_op() -> Operation:
    return Operation(
        operation_id="op",
        method="POST",
        path="/things/{id}",
        parameters=(
            Parameter("id", "path", True, {"type": "integer"}),
            Parameter("q", "query", False, {"type": "string"}),
        ),
        body_schema={
            "type": "object",
            "required": ["name"],
            "properties": {"name": {"type": "string"}, "count": {"type": "integer"}},
        },
        body_required=True,
    )


def test_baseline_fills_path_placeholders():
    case = CaseBuilder(sample_op(), rng()).baseline()
    assert "{" not in case.path
    assert case.is_baseline


def test_baseline_body_satisfies_required():
    case = CaseBuilder(sample_op(), rng()).baseline()
    assert "name" in case.body


def test_mutated_case_records_its_mutation():
    builder = CaseBuilder(sample_op(), rng())
    # Not every draw mutates (some target sets are empty), so sample a few.
    mutated = [builder.mutated() for _ in range(30)]
    assert any(c.mutations for c in mutated)
    assert all(not c.is_baseline for c in mutated)


def test_path_placeholders_always_filled_even_when_unmutated():
    builder = CaseBuilder(sample_op(), rng())
    for _ in range(30):
        assert "{" not in builder.mutated().path


def test_build_cases_is_deterministic_for_a_seed():
    ops = [sample_op()]
    a = [(c.method, c.path, c.label) for c in build_cases(ops, 10, seed=99)]
    b = [(c.method, c.path, c.label) for c in build_cases(ops, 10, seed=99)]
    assert a == b


def test_build_cases_emits_baseline_plus_n():
    cases = list(build_cases([sample_op()], 5, seed=1))
    assert len(cases) == 6
    assert sum(c.is_baseline for c in cases) == 1
