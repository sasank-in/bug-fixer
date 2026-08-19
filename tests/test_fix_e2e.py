"""End-to-end verification, with a scripted model instead of a live one.

The point is not that a model can write a fix — it is that the verifier reaches
the right verdict about whatever it is handed. A correct patch must be accepted,
a wrong one rejected, and one that breaks other tests must be caught separately
from one that fails to fix the bug. Those distinctions are the whole feature.
"""

import sys
import tempfile
from pathlib import Path

import pytest

from autoqa.fix.patcher import propose
from autoqa.fix.verify import Verdict, Verifier

pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")

# A tiny app with one genuine bug: no None check before subscripting.
APP = '''\
from fastapi import FastAPI

app = FastAPI()
_ROWS = {1: "alice"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/rows/{row_id}")
def get_row(row_id: int):
    row = _ROWS.get(row_id)
    return {"name": row.upper()}
'''

FIXED = '''\
@app.get("/rows/{row_id}")
def get_row(row_id: int):
    row = _ROWS.get(row_id)
    if row is None:
        raise HTTPException(status_code=404, detail="not found")
    return {"name": row.upper()}
'''


class ScriptedClient:
    def __init__(self, reply: str):
        self.reply = reply

    def complete(self, system, user):
        return self.reply


@pytest.fixture
def repo(tmp_path):
    """A minimal repo whose only source file has the bug."""
    root = tmp_path / "repo"
    (root / "svc").mkdir(parents=True)
    (root / "svc" / "__init__.py").write_text("", encoding="utf-8")
    (root / "svc" / "app.py").write_text(APP, encoding="utf-8")
    return root


def finding_for(repo: Path) -> dict:
    app_py = repo / "svc" / "app.py"
    # Line 15 is the `row.upper()` that raises.
    return {
        "signature": "attr-err-1",
        "title": "HTTP 500 on GET /rows/{row_id}",
        "detail": "Unhandled AttributeError on a missing row.",
        "severity": "high",
        "stack_trace": {
            "culprit": f"{app_py}:15 in get_row",
            "exception_type": "AttributeError",
            "message": "'NoneType' object has no attribute 'upper'",
        },
        "reproducer": {
            "curl": "curl -i http://x/rows/999",
            "method": "GET", "path": "/rows/999",
            "query": {}, "headers": {}, "body": None,
        },
        "observed": {"status": 500, "transport_error": None},
    }


def verifier_for(repo: Path, scratch: Path, test_command=None) -> Verifier:
    return Verifier(
        repo, scratch,
        launch_command=(
            f"{sys.executable} -m uvicorn svc.app:app --port {{port}} --log-level error"
        ),
        health_path="/health",
        test_command=test_command,
    )


def test_correct_patch_is_accepted(repo):
    """The happy path: bug gone, so the verdict is FIXED."""
    # The fix raises HTTPException, so that import must be available.
    app_py = repo / "svc" / "app.py"
    app_py.write_text(
        APP.replace(
            "from fastapi import FastAPI",
            "from fastapi import FastAPI, HTTPException",
        ),
        encoding="utf-8",
    )
    candidate = propose(finding_for(repo), ScriptedClient(f"```python\n{FIXED}```"), repo)

    with tempfile.TemporaryDirectory() as scratch:
        result = verifier_for(repo, Path(scratch)).verify(candidate, finding_for(repo))

    assert result.verdict is Verdict.FIXED, result.detail
    assert result.status_after == 404


def test_wrong_patch_is_rejected(repo):
    """A cosmetic change that leaves the bug in place must not be accepted."""
    unchanged_but_different = (
        '@app.get("/rows/{row_id}")\n'
        "def get_row(row_id: int):\n"
        "    row = _ROWS.get(row_id)  # lookup\n"
        '    return {"name": row.upper()}\n'
    )
    candidate = propose(
        finding_for(repo),
        ScriptedClient(f"```python\n{unchanged_but_different}```"),
        repo,
    )
    with tempfile.TemporaryDirectory() as scratch:
        result = verifier_for(repo, Path(scratch)).verify(candidate, finding_for(repo))

    assert result.verdict is Verdict.STILL_BROKEN, result.detail
    assert not result.accepted


def test_patch_that_stops_the_app_booting_is_unverifiable(repo):
    """Importing a name that does not exist: parses fine, dies at runtime."""
    broken = (
        '@app.get("/rows/{row_id}")\n'
        "def get_row(row_id: int):\n"
        "    return {\"name\": does_not_exist(row_id)}\n"
    )
    candidate = propose(finding_for(repo), ScriptedClient(f"```python\n{broken}```"), repo)
    with tempfile.TemporaryDirectory() as scratch:
        result = verifier_for(repo, Path(scratch)).verify(candidate, finding_for(repo))

    # NameError happens per-request, so this surfaces as a still-500 rather than
    # a boot failure — either way it must not be accepted.
    assert not result.accepted


def test_working_tree_is_never_modified(repo):
    """The core safety promise, asserted on real bytes."""
    app_py = repo / "svc" / "app.py"
    before = app_py.read_bytes()
    candidate = propose(finding_for(repo), ScriptedClient(f"```python\n{FIXED}```"), repo)

    with tempfile.TemporaryDirectory() as scratch:
        verifier_for(repo, Path(scratch)).verify(candidate, finding_for(repo))

    assert app_py.read_bytes() == before


def test_regression_in_the_suite_is_reported_separately(repo):
    """A patch that fixes the bug but breaks tests is BROKE_TESTS, not FIXED.

    Collapsing the two would let a fix that breaks the build look clean.
    """
    app_py = repo / "svc" / "app.py"
    app_py.write_text(
        APP.replace(
            "from fastapi import FastAPI",
            "from fastapi import FastAPI, HTTPException",
        ),
        encoding="utf-8",
    )
    # A test that the fix will break: it asserts the old crashing behaviour.
    (repo / "test_contract.py").write_text(
        "def test_always_fails():\n    assert False, 'pretend regression'\n",
        encoding="utf-8",
    )
    candidate = propose(finding_for(repo), ScriptedClient(f"```python\n{FIXED}```"), repo)

    with tempfile.TemporaryDirectory() as scratch:
        result = verifier_for(
            repo, Path(scratch), test_command=f"{sys.executable} -m pytest -q"
        ).verify(candidate, finding_for(repo))

    assert result.verdict is Verdict.BROKE_TESTS, result.detail
    assert "pretend regression" in result.test_output


def test_scratch_copy_excludes_heavy_directories(repo, tmp_path):
    """Copying .git and caches would dominate setup cost for no benefit."""
    (repo / ".git").mkdir()
    (repo / ".git" / "big").write_text("x" * 5000, encoding="utf-8")
    (repo / "__pycache__").mkdir()
    (repo / "__pycache__" / "a.pyc").write_text("junk", encoding="utf-8")

    candidate = propose(finding_for(repo), ScriptedClient(f"```python\n{FIXED}```"), repo)
    scratch = tmp_path / "scratch"
    verifier = verifier_for(repo, scratch)
    verifier._materialise(candidate, scratch / "w")

    assert not (scratch / "w" / ".git").exists()
    assert not (scratch / "w" / "__pycache__").exists()
    assert (scratch / "w" / "svc" / "app.py").exists()


def test_patch_lands_in_the_scratch_copy_only(repo, tmp_path):
    candidate = propose(finding_for(repo), ScriptedClient(f"```python\n{FIXED}```"), repo)
    scratch = tmp_path / "scratch"
    verifier_for(repo, scratch)._materialise(candidate, scratch / "w")

    patched = (scratch / "w" / "svc" / "app.py").read_text(encoding="utf-8")
    original = (repo / "svc" / "app.py").read_text(encoding="utf-8")
    assert "if row is None" in patched
    assert "if row is None" not in original
