"""Launch the target application and capture its output.

Server logs are where the real diagnosis lives: an HTTP 500 tells you a request
broke something, but the stack trace on stderr tells you where. This module
keeps a timestamped ring buffer of output so findings can be correlated with
the requests that produced them.
"""

from __future__ import annotations

import shlex
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path

import httpx


@dataclass(frozen=True)
class LogLine:
    timestamp: float
    stream: str
    text: str


class TargetProcess:
    """Runs the target under test as a subprocess, tailing its output."""

    def __init__(
        self,
        command: str,
        *,
        cwd: str | Path | None = None,
        env: dict[str, str] | None = None,
        buffer_size: int = 20_000,
    ) -> None:
        self.command = command
        self.cwd = str(cwd) if cwd else None
        self.env = env
        self._lines: deque[LogLine] = deque(maxlen=buffer_size)
        self._lock = threading.Lock()
        self._process: subprocess.Popen[str] | None = None
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        if self._process is not None:
            raise RuntimeError("process already started")
        # shell=False with a parsed argv avoids the shell mangling our command
        # on Windows, where posix-style quoting would otherwise be misread.
        args = shlex.split(self.command, posix=(sys.platform != "win32"))
        self._process = subprocess.Popen(
            args,
            cwd=self.cwd,
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        for name, pipe in (("stdout", self._process.stdout), ("stderr", self._process.stderr)):
            thread = threading.Thread(
                target=self._pump, args=(name, pipe), daemon=True, name=f"tail-{name}"
            )
            thread.start()
            self._threads.append(thread)

    def _pump(self, stream: str, pipe) -> None:
        if pipe is None:
            return
        for raw in pipe:
            with self._lock:
                self._lines.append(LogLine(time.time(), stream, raw.rstrip("\n")))

    def wait_until_ready(
        self, health_url: str, *, timeout: float = 30.0, interval: float = 0.4
    ) -> bool:
        """Poll `health_url` until it answers or `timeout` elapses."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._process and self._process.poll() is not None:
                return False  # died during startup
            try:
                response = httpx.get(health_url, timeout=2.0)
                if response.status_code < 500:
                    return True
            except Exception:
                # Intentionally broad and silent: "not listening yet" is the
                # expected state for most of this loop, and it surfaces as a
                # different exception per platform and transport. The timeout
                # above is what distinguishes slow startup from real failure.
                pass
            time.sleep(interval)
        return False

    def lines_since(self, since: float) -> list[LogLine]:
        with self._lock:
            return [line for line in self._lines if line.timestamp >= since]

    def all_lines(self) -> list[LogLine]:
        with self._lock:
            return list(self._lines)

    @property
    def is_alive(self) -> bool:
        return self._process is not None and self._process.poll() is None

    @property
    def exit_code(self) -> int | None:
        return self._process.poll() if self._process else None

    def stop(self, grace: float = 5.0) -> None:
        if self._process is None or self._process.poll() is not None:
            return
        self._process.terminate()
        try:
            self._process.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait(timeout=grace)

    def __enter__(self) -> TargetProcess:
        self.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()
