"""Stateful sequence fuzzing.

Every other strategy here sends independent requests, which makes whole classes
of bug unreachable. Use-after-delete, double-delete, broken pagination, and
non-idempotent state machines only appear when one request acts on state a
previous request created. A fuzzer that never chains calls will report those
endpoints as clean.

The approach:

1. Group operations into *resources* by collection path, so `/notes`,
   `/notes/{id}`, and `/notes/{id}/publish` are recognised as one thing.
2. Order them into abuse patterns that target a known failure mode —
   create-then-double-delete, create-delete-read, and so on.
3. Run each step for real, extracting the created id from the response and
   substituting it into later steps.

Step 3 is what makes this different from replaying a static script: the id
cannot be known ahead of time, so the chain has to be resolved as it executes.
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass, field
from typing import Any

from autoqa.fuzz.engine import CaseBuilder, TestCase
from autoqa.spec.parser import Operation

# Response fields that plausibly identify a created resource, best first.
_ID_FIELDS = ("id", "uuid", "key", "name", "slug", "_id", "identifier")


@dataclass(frozen=True)
class Resource:
    """One collection and the operations that act on it."""

    collection: str
    create: Operation | None = None
    list_: Operation | None = None
    read: Operation | None = None
    update: Operation | None = None
    delete: Operation | None = None
    actions: tuple[Operation, ...] = ()

    @property
    def is_fuzzable(self) -> bool:
        """A sequence needs something to create with and something to act on."""
        return self.create is not None and any(
            (self.read, self.update, self.delete, self.actions)
        )


@dataclass
class Step:
    """One request in a sequence, plus what to do with its response."""

    operation: Operation
    # Where the id for this step's path parameter comes from: the index of an
    # earlier step whose response carried one. None means no substitution.
    id_from_step: int | None = None
    # Deliberately reuse an id that an earlier step deleted.
    expect_failure: bool = False
    note: str = ""


@dataclass
class Sequence:
    """An ordered chain of requests targeting one stateful failure mode."""

    name: str
    resource: str
    steps: list[Step] = field(default_factory=list)
    # What makes this sequence interesting, surfaced in the report so a finding
    # explains why the ordering mattered.
    hypothesis: str = ""

    @property
    def label(self) -> str:
        return f"{self.name} on {self.resource}"


def _collection_of(operation: Operation) -> str:
    """The collection an operation belongs to.

    Everything from the first `{param}` onward is stripped, so `/notes`,
    `/notes/{id}` and `/notes/{id}/publish` all resolve to `/notes` and end up
    in one resource. Grouping on the immediate parent instead would file
    sub-path actions under `/notes/{id}` and orphan them from the create
    operation they depend on.
    """
    path = operation.path
    if "/{" in path:
        return path[: path.index("/{")] or "/"
    return path


def discover_resources(operations: list[Operation]) -> list[Resource]:
    """Group operations by the collection they operate on."""
    by_collection: dict[str, list[Operation]] = {}
    for op in operations:
        by_collection.setdefault(_collection_of(op), []).append(op)

    resources: list[Resource] = []
    for collection, ops in sorted(by_collection.items()):
        create = list_ = read = update = delete = None
        actions: list[Operation] = []

        for op in ops:
            has_path_param = bool(op.path_params)
            # A sub-path like /notes/{id}/publish is an action, never the
            # canonical read/update/delete for the resource.
            is_sub_path = has_path_param and not op.path.endswith("}")

            if is_sub_path:
                if op.method in ("POST", "PUT", "PATCH"):
                    actions.append(op)
            elif op.method == "POST" and not has_path_param:
                create = create or op
            elif op.method == "GET" and not has_path_param:
                list_ = list_ or op
            elif op.method == "GET":
                read = read or op
            elif op.method in ("PUT", "PATCH"):
                update = update or op
            elif op.method == "DELETE":
                delete = delete or op
            elif op.method == "POST":
                actions.append(op)

        resources.append(
            Resource(collection, create, list_, read, update, delete, tuple(actions))
        )

    return [r for r in resources if r.is_fuzzable]


def build_sequences(resource: Resource) -> list[Sequence]:
    """Abuse patterns worth running against one resource.

    Each targets a specific failure mode rather than exploring randomly —
    sequence space is far too large to sample usefully, and these are the
    orderings that break real APIs.
    """
    out: list[Sequence] = []
    create = resource.create
    assert create is not None  # guaranteed by is_fuzzable

    if resource.delete:
        out.append(Sequence(
            "double_delete", resource.collection,
            [Step(create, note="create the resource"),
             Step(resource.delete, id_from_step=0, note="first delete should succeed"),
             Step(resource.delete, id_from_step=0, expect_failure=True,
                  note="second delete must 404, not crash")],
            hypothesis="deleting twice should be idempotent or 404, never 5xx",
        ))

    if resource.delete and resource.read:
        out.append(Sequence(
            "read_after_delete", resource.collection,
            [Step(create, note="create the resource"),
             Step(resource.delete, id_from_step=0, note="delete it"),
             Step(resource.read, id_from_step=0, expect_failure=True,
                  note="reading a deleted id must 404, not crash")],
            hypothesis="a deleted resource must be gone, not half-remembered",
        ))

    if resource.delete and resource.update:
        out.append(Sequence(
            "update_after_delete", resource.collection,
            [Step(create), Step(resource.delete, id_from_step=0),
             Step(resource.update, id_from_step=0, expect_failure=True,
                  note="updating a deleted id must 404")],
            hypothesis="writes to a deleted resource must be rejected",
        ))

    for action in resource.actions:
        out.append(Sequence(
            f"repeat_{_action_name(action)}", resource.collection,
            [Step(create),
             Step(action, id_from_step=0, note="first invocation"),
             Step(action, id_from_step=0, note="repeat must be idempotent")],
            hypothesis="repeating a state-changing action must not double-apply",
        ))
        if resource.delete:
            out.append(Sequence(
                f"{_action_name(action)}_after_delete", resource.collection,
                [Step(create), Step(resource.delete, id_from_step=0),
                 Step(action, id_from_step=0, expect_failure=True,
                      note="action on a deleted resource must 404")],
                hypothesis="state transitions must be rejected after deletion",
            ))

    if resource.read and resource.update:
        out.append(Sequence(
            "update_then_read", resource.collection,
            [Step(create), Step(resource.update, id_from_step=0),
             Step(resource.read, id_from_step=0, note="must reflect the update")],
            hypothesis="a read after a write must return the written value",
        ))

    return out


def _action_name(op: Operation) -> str:
    """`/notes/{id}/publish` -> `publish`."""
    tail = op.path.rstrip("/").rsplit("/", 1)[-1]
    return re.sub(r"[^a-z0-9]+", "_", tail.lower()) or "action"


def extract_id(body: Any, schema: dict[str, Any] | None = None) -> Any:
    """Pull the most likely resource identifier out of a response body.

    Prefers conventional field names over position: an object with both `id`
    and `owner` should yield the `id`, not whichever key happens to come first.
    """
    if isinstance(body, dict):
        for field_name in _ID_FIELDS:
            if field_name in body and _usable_id(body[field_name]):
                return body[field_name]
        # Recurse only into containers. A single-key wrapper like
        # {"data": {...}} is worth unwrapping, but {"title": "hello"} is not an
        # id just because it is the only field — substituting a note's title
        # into a path would silently produce nonsense requests.
        for value in body.values():
            if isinstance(value, (dict, list)):
                found = extract_id(value, schema)
                if found is not None:
                    return found
    elif isinstance(body, list) and body:
        return extract_id(body[0], schema)
    return None


def _usable_id(value: Any) -> bool:
    """Whether a value can be substituted into a path segment."""
    if isinstance(value, bool) or value is None:
        return False
    if isinstance(value, int):
        return True
    return isinstance(value, str) and 0 < len(value) < 200


def realise_step(
    step: Step, resource_id: Any, rng: random.Random
) -> TestCase:
    """Build the concrete request for one step, with `resource_id` substituted."""
    builder = CaseBuilder(step.operation, rng)
    case = builder.baseline()

    if step.id_from_step is not None and resource_id is not None:
        params = step.operation.path_params
        if params:
            from urllib.parse import quote

            # Substitute into the *template*, since case.path already has a
            # generated value filled in.
            path = step.operation.path
            for prm in params:
                path = path.replace(
                    f"{{{prm.name}}}", quote(str(resource_id), safe="")
                )
            case.path = path

    return case
