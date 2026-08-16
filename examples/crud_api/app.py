"""A CRUD API with deliberate *stateful* bugs.

The vulnerable_api demo has bugs reachable in one request. These need a
sequence: create something, then act on it, then act on it again. No amount of
single-request fuzzing finds them, which is exactly the point — this is the
target that proves sequence fuzzing works.

    python -m uvicorn examples.crud_api.app:app --port 8100
"""

from __future__ import annotations

from typing import Any

from fastapi import Body, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel

app = FastAPI(title="CRUD Demo API", version="1.0.0")

_NOTES: dict[int, dict[str, Any]] = {}
_DELETED: set[int] = set()
_NEXT_ID = {"value": 1}


class NoteIn(BaseModel):
    title: str
    body: str = ""
    owner: str = "anonymous"


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/notes", status_code=201)
def create_note(note: NoteIn) -> Any:
    note_id = _NEXT_ID["value"]
    _NEXT_ID["value"] += 1
    _NOTES[note_id] = {
        "id": note_id,
        "title": note.title,
        "body": note.body,
        "owner": note.owner,
        "version": 1,
    }
    return _NOTES[note_id]


@app.get("/notes/{note_id}")
def get_note(note_id: int, x_user: str = Header(default="anonymous")) -> Any:
    # STATEFUL BUG 1: use-after-delete. A deleted id is removed from _NOTES but
    # remembered in _DELETED, and this path dereferences before checking.
    if note_id in _DELETED:
        return {"id": note_id, "title": _NOTES[note_id]["title"]}  # KeyError

    note = _NOTES.get(note_id)
    if note is None:
        raise HTTPException(status_code=404, detail="not found")

    # STATEFUL BUG 2: IDOR. Ownership is never checked, so any user can read
    # any note simply by knowing its id.
    return note


@app.put("/notes/{note_id}")
def update_note(note_id: int, note: NoteIn) -> Any:
    existing = _NOTES.get(note_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="not found")
    # STATEFUL BUG 3: version is incremented but never bounded, and a second
    # update of an already-deleted-then-recreated id corrupts the counter.
    existing.update(title=note.title, body=note.body, owner=note.owner)
    existing["version"] += 1
    return existing


@app.delete("/notes/{note_id}", status_code=204)
def delete_note(note_id: int) -> None:
    # STATEFUL BUG 4: double delete. The second call pops a missing key.
    if note_id in _DELETED:
        _NOTES.pop(note_id)  # KeyError on the second delete
        return None
    if note_id in _NOTES:
        del _NOTES[note_id]
        _DELETED.add(note_id)
        return None
    raise HTTPException(status_code=404, detail="not found")


@app.get("/notes")
def list_notes(limit: int = Query(10), offset: int = Query(0)) -> Any:
    items = sorted(_NOTES.values(), key=lambda n: n["id"])
    # STATEFUL BUG 5: negative offset wraps around and leaks the tail of the
    # list, which pagination callers never expect.
    window = items[offset : offset + limit]
    return {"total": len(items), "items": window}


@app.post("/notes/{note_id}/publish")
def publish_note(note_id: int, payload: dict = Body(default={})) -> Any:
    note = _NOTES.get(note_id)
    if note is None:
        raise HTTPException(status_code=404, detail="not found")
    # STATEFUL BUG 6: no idempotency. Publishing twice double-applies, and the
    # state machine allows publish after delete.
    note["published"] = note.get("published", 0) + 1
    if note["published"] > 1:
        raise HTTPException(status_code=500, detail="already published")
    return note
