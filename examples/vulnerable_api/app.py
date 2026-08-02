"""A deliberately buggy API used to validate that AutoQA finds real defects.

Every bug here is intentional and is the kind of thing that ships to production:
missing null checks, unvalidated arithmetic, string-built SQL, unbounded work.
Run it, point AutoQA at it, and each one should show up in the report.

    python -m uvicorn examples.vulnerable_api.app:app --port 8000
"""

from __future__ import annotations

import sqlite3
import time
from typing import Any

from fastapi import Body, FastAPI, Query
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel

app = FastAPI(title="Vulnerable Demo API", version="1.0.0")

_db = sqlite3.connect(":memory:", check_same_thread=False)
_db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, role TEXT)")
_db.execute("INSERT INTO users VALUES (1, 'alice', 'admin'), (2, 'bob', 'user')")
_db.commit()

_ACCOUNTS: dict[str, float] = {"acct-1": 100.0, "acct-2": 50.0}


class Order(BaseModel):
    item: str
    quantity: int
    price: float
    note: str | None = None


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/users/{user_id}")
def get_user(user_id: str) -> Any:
    # BUG 1: string-interpolated SQL. Injectable, and malformed input raises
    # an OperationalError that escapes as a 500 with the query in the message.
    cursor = _db.execute(f"SELECT id, name, role FROM users WHERE id = {user_id}")
    row = cursor.fetchone()
    # BUG 2: no None check. A valid-but-missing id crashes on subscript.
    return {"id": row[0], "name": row[1], "role": row[2]}


@app.get("/search")
def search(q: str = Query(...), limit: int = Query(10)) -> Any:
    # BUG 3: unbounded limit. A large value burns CPU and stalls the worker.
    results = [{"idx": i, "match": q} for i in range(limit)]
    if limit > 50_000:
        time.sleep(3)  # simulates the pathological path this exposes
    return {"count": len(results), "results": results[:100]}


@app.post("/orders")
def create_order(order: Order) -> Any:
    # BUG 4: division by zero when quantity is 0.
    unit = order.price / order.quantity
    # BUG 5: negative quantity produces a negative total, no validation.
    total = order.price * order.quantity
    return {"unit_price": unit, "total": total, "item": order.item}


@app.post("/transfer")
def transfer(payload: dict = Body(...)) -> Any:
    # BUG 6: unchecked key access raises KeyError -> 500 instead of 400.
    source = payload["from"]
    dest = payload["to"]
    amount = float(payload["amount"])
    # BUG 7: no balance check, negative amounts drain the destination.
    _ACCOUNTS[source] = _ACCOUNTS.get(source, 0) - amount
    _ACCOUNTS[dest] = _ACCOUNTS.get(dest, 0) + amount
    return {"from": source, "to": dest, "balance": _ACCOUNTS[source]}


@app.get("/render")
def render(template: str = Query("Hello")) -> Any:
    # BUG 8: server-side template evaluation of user input.
    try:
        if "{{" in template and "}}" in template:
            expression = template.split("{{")[1].split("}}")[0]
            return PlainTextResponse(str(eval(expression, {"__builtins__": {}}, {})))
    except Exception as exc:
        # BUG 9: exception detail leaked straight to the client.
        return JSONResponse({"error": str(exc), "template": template}, status_code=500)
    return PlainTextResponse(template)


@app.get("/files")
def read_file(name: str = Query("readme.txt")) -> Any:
    # BUG 10: path traversal, and the OS error leaks the absolute path.
    try:
        with open(name, encoding="utf-8", errors="replace") as handle:
            return PlainTextResponse(handle.read()[:2000])
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)
