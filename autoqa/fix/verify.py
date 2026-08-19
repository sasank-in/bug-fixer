"""Decide whether a proposed patch actually works.

This is the module that makes the fix layer trustworthy. A model can produce
confident, plausible, wrong code, and no amount of reading the diff reliably
catches that. So nothing here reads the patch — it runs it:

1. Copy the repo to a scratch directory and apply the patch there. The real
   working tree is never touched.
2. Start the patched target and replay the exact reproducer. The claimed status
   must be gone.
3. Run the test suite in the patched copy. A patch that fixes the bug by
   breaking three other things is not a fix.

A candidate that fails any step is reported as rejected, with the reason, rather
than quietly dropped — a rejected patch is still useful information about the
bug.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

import httpx

from autoqa.fix.patcher import Candidate
from autoqa.runner.http import encode_body, with_default_content_type

# Directories never worth copying into the scratch tree. Copying .git alone can
# dominate the setup cost and none of it affects the verification.
_SKIP = shutil.ignore_patterns(
    ".git", "__pycache__", "*.pyc", ".pytest_cache", ".ruff_cache",
    ".venv", "venv", "node_modules", "*.egg-info", ".mypy_cache",
)


class Verdict(str, Enum):
    FIXED = "fixed"                    # bug gone, tests still pass
    STILL_BROKEN = "still_broken"      # reproducer still fails
    BROKE_TESTS = "broke_tests"        # bug gone but suite regressed
    UNVERIFIABLE = "unverifiable"      # could not run the check


@dataclass
class VerifyResult:
    candidate: Candidate
    verdict: Verdict
    detail: str = ""
    # Status the reproducer returned after patching, when it could be measured.
    status_after: int | None = None
    test_output: str = ""

    @property
    def accepted(self) -> bool:
        return self.verdict is Verdict.FIXED


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Verifier:
    """Applies a candidate in a scratch copy and measures the result."""

    def __init__(
        self,
        repo_root: Path,
        scratch_root: Path,
        *,
        launch_command: str,
        health_path: str = "/health",
        test_command: str | None = None,
        startup_timeout: float = 45.0,
    ) -> None:
        self.repo_root = repo_root.resolve()
        self.scratch_root = scratch_root
        self.launch_command = launch_command
        self.health_path = health_path
        self.test_command = test_command
        self.startup_timeout = startup_timeout

    def verify(self, candidate: Candidate, finding: dict) -> VerifyResult:
        workdir = self.scratch_root / f"patched-{candidate.signature[:16]}"
        try:
            self._materialise(candidate, workdir)
        except OSError as exc:
            return VerifyResult(
                candidate, Verdict.UNVERIFIABLE, f"could not prepare scratch copy: {exc}"
            )

        try:
            reproduced = self._replay(candidate, finding, workdir)
        except RuntimeError as exc:
            return VerifyResult(candidate, Verdict.UNVERIFIABLE, str(exc))

        status_after, claimed = reproduced
        if _same_failure(status_after, claimed):
            return VerifyResult(
                candidate,
                Verdict.STILL_BROKEN,
                f"reproducer still returns {status_after} (claimed {claimed})",
                status_after=status_after,
            )

        if self.test_command:
            ok, output = self._run_tests(workdir)
            if not ok:
                return VerifyResult(
                    candidate,
                    Verdict.BROKE_TESTS,
                    "bug is fixed but the test suite regressed",
                    status_after=status_after,
                    test_output=output[-3000:],
                )

        return VerifyResult(
            candidate,
            Verdict.FIXED,
            f"reproducer now returns {status_after}; test suite still passes"
            if self.test_command
            else f"reproducer now returns {status_after} (tests not run)",
            status_after=status_after,
        )

    # -- internals ---------------------------------------------------------

    def _materialise(self, candidate: Candidate, workdir: Path) -> None:
        if workdir.exists():
            shutil.rmtree(workdir)
        workdir.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(self.repo_root, workdir, ignore=_SKIP)

        relative = candidate.file.resolve().relative_to(self.repo_root)
        target = workdir / relative
        original = target.read_text(encoding="utf-8")
        target.write_text(candidate.apply_to(original), encoding="utf-8")

    def _replay(
        self, candidate: Candidate, finding: dict, workdir: Path
    ) -> tuple[int | None, int | None]:
        """Start the patched target and re-send the reproducer."""
        port = free_port()
        command = self.launch_command.replace("{port}", str(port))
        process = subprocess.Popen(
            command.split(),
            cwd=str(workdir),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        base = f"http://127.0.0.1:{port}"
        try:
            if not self._wait_ready(process, base):
                # A patch that stops the app from booting is a failed patch, not
                # an unverifiable one — but say which, since the causes differ.
                _, stderr = _drain(process)
                raise RuntimeError(
                    f"patched target never became ready; it may not import. "
                    f"Last output: {stderr[-400:]}"
                )
            return self._send(finding, base)
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()

    def _wait_ready(self, process: subprocess.Popen, base: str) -> bool:
        deadline = time.monotonic() + self.startup_timeout
        while time.monotonic() < deadline:
            if process.poll() is not None:
                return False
            try:
                if httpx.get(base + self.health_path, timeout=2.0).status_code < 500:
                    return True
            except Exception:
                # Not listening yet is the expected state for most of this loop.
                time.sleep(0.4)
        return False

    def _send(self, finding: dict, base: str) -> tuple[int | None, int | None]:
        repro = finding.get("reproducer") or {}
        observed = finding.get("observed") or {}
        claimed = observed.get("status")

        url = base + repro.get("path", "/")
        query = repro.get("query") or {}
        if query:
            try:
                url = str(httpx.URL(url).copy_merge_params(query))
            except httpx.InvalidURL:
                from urllib.parse import urlencode

                url += "?" + urlencode(
                    [(k, "" if v is None else str(v)) for k, v in query.items()]
                )

        headers = dict(repro.get("headers") or {})
        body = repro.get("body")
        content = None
        if body is not None:
            headers = with_default_content_type(headers)
            content = encode_body(body)

        try:
            response = httpx.request(
                repro.get("method", "GET"), url,
                headers=headers or None, content=content,
                timeout=15.0, follow_redirects=False,
            )
            return response.status_code, claimed
        except httpx.TimeoutException:
            # A hang is not "could not check" — it is the bug still present, and
            # often the same crash the patch was meant to remove (an unhandled
            # exception can leave the worker holding the connection open).
            # Reporting it as unverifiable would let a failed patch look
            # inconclusive instead of rejected.
            return None, claimed
        except httpx.TransportError:
            # Likewise a reset: the patched server still mishandles this input.
            return None, claimed
        except Exception as exc:
            raise RuntimeError(f"could not replay the reproducer: {exc}") from exc

    def _run_tests(self, workdir: Path) -> tuple[bool, str]:
        assert self.test_command is not None
        try:
            completed = subprocess.run(
                self.test_command.split(),
                cwd=str(workdir),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=600,
            )
        except subprocess.TimeoutExpired:
            return False, "test command timed out after 600s"
        except OSError as exc:
            return False, f"could not run tests: {exc}"
        output = (completed.stdout or "") + (completed.stderr or "")
        return completed.returncode == 0, output


def _same_failure(after: int | None, claimed: int | None) -> bool:
    """Whether the bug is still present after patching."""
    if after is None:
        return True  # could not get a response at all
    if claimed is None:
        # The original was a transport failure; any real response is progress.
        return False
    if claimed >= 500:
        # A 5xx must be gone. Any 4xx or 2xx counts as handled, since rejecting
        # invalid input with a 4xx is the correct fix.
        return after >= 500
    return after == claimed


def _drain(process: subprocess.Popen) -> tuple[str, str]:
    try:
        return process.communicate(timeout=5)
    except Exception:
        return "", ""


def load_report(path: Path) -> list[dict]:
    """Read clusters out of a JSON report."""
    data = json.loads(path.read_text(encoding="utf-8"))
    clusters = data.get("clusters")
    if not isinstance(clusters, list):
        raise ValueError(f"{path} does not look like an AutoQA JSON report")
    return clusters


def default_test_command() -> str:
    return f"{sys.executable} -m pytest -q -x"
