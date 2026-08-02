"""Extract stack traces from captured log output.

Supports Python, Node/JS, Java/JVM and Go panic formats. The goal is a
`StackTrace` whose `signature` is stable across runs so the same underlying
bug clusters together even when line noise differs.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from autoqa.runner.process import LogLine


# Path fragments that mark a frame as dependency or runtime code rather than
# the application under test. Compared against a forward-slashed, lowercased
# path so Windows and POSIX layouts both match.
_LIBRARY_MARKERS: tuple[str, ...] = (
    "site-packages",
    "dist-packages",
    "node_modules",
    "/usr/lib/",
    "/usr/local/lib/",
    "<frozen",
    "<string>",
    "/lib/python",
    "/go/pkg/",
    "/jre/",
    "/jdk/",
    "internal/modules/",  # Node bootstrap frames
    "asyncio/",
    "concurrent/futures/",
    "threading.py",
)


def _is_library(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    return any(marker in normalized for marker in _LIBRARY_MARKERS)


@dataclass
class Frame:
    file: str = ""
    line: int | None = None
    function: str = ""

    @property
    def is_library(self) -> bool:
        return _is_library(self.file)

    def short(self) -> str:
        loc = f"{self.file}:{self.line}" if self.line else self.file
        return f"{loc} in {self.function}" if self.function else loc


@dataclass
class StackTrace:
    language: str
    exception_type: str
    message: str
    frames: list[Frame] = field(default_factory=list)
    raw: str = ""
    # When the target logged this trace, used to correlate it with the request
    # that was in flight at the time.
    timestamp: float = 0.0

    @property
    def app_frames(self) -> list[Frame]:
        """Frames that look like application code rather than dependencies."""
        return [f for f in self.frames if not _is_library(f.file)]

    @property
    def culprit(self) -> Frame | None:
        """The deepest application frame — where a fix most likely belongs.

        Returns None when the trace contains no application code at all (a
        crash entirely inside the server or a dependency). Pointing at a
        library internal would send someone editing the wrong file, so an
        honest "unknown" is more useful than a confident wrong answer.
        """
        app = self.app_frames
        return app[-1] if app else None

    @property
    def deepest_frame(self) -> Frame | None:
        """The deepest frame of any kind, for when no app frame exists."""
        return self.frames[-1] if self.frames else None

    @property
    def in_dependency(self) -> bool:
        """True when the failure never reaches application code."""
        return bool(self.frames) and not self.app_frames

    @property
    def signature(self) -> str:
        """Stable identity for deduplication.

        Uses exception type plus the top few app frames' file:function, but
        NOT line numbers or the message, so the same bug still clusters after
        an unrelated edit shifts the file or a message embeds a random id.
        """
        parts = [self.exception_type]
        for frame in (self.app_frames or self.frames)[-3:]:
            parts.append(f"{frame.file}:{frame.function}")
        digest = hashlib.sha256("|".join(parts).encode()).hexdigest()[:12]
        return f"{self.exception_type}@{digest}"


_PY_FRAME = re.compile(r'^\s*File "(?P<file>[^"]+)", line (?P<line>\d+), in (?P<func>.+)$')
# The exception line that closes a Python traceback. Accepts bare
# (`KeyError: x`), dotted (`sqlite3.OperationalError: x`), and deeply dotted
# (`psycopg2.errors.UniqueViolation: x`) names. The final segment must be
# CamelCase, which is what distinguishes an exception line from arbitrary log
# text that happens to sit at column 0.
_PY_EXC = re.compile(
    r"^(?P<type>(?:[A-Za-z_]\w*\.)*[A-Z][A-Za-z0-9_]*)"
    r"(?::\s*(?P<msg>.*))?$"
)

_JS_FRAME = re.compile(
    r"^\s*at\s+(?:(?P<func>[^\s(]+)\s+\()?(?P<file>[^\s()]+?):(?P<line>\d+):\d+\)?$"
)
_JS_EXC = re.compile(r"^(?:Uncaught\s+)?(?P<type>[A-Za-z_]\w*(?:Error|Exception))\b:?\s*(?P<msg>.*)$")

_JAVA_FRAME = re.compile(
    r"^\s*at\s+(?P<func>[\w$.]+)\((?P<file>[^:)]+)(?::(?P<line>\d+))?\)"
)
_JAVA_EXC = re.compile(
    r"^(?:Caused by:\s*)?(?P<type>(?:[a-z]\w*\.)+[A-Z]\w*(?:Error|Exception))\b:?\s*(?P<msg>.*)$"
)

_GO_PANIC = re.compile(r"^panic:\s*(?P<msg>.*)$")
_GO_FRAME = re.compile(r"^\s+(?P<file>[^\s:]+\.go):(?P<line>\d+)")


def extract_traces(lines: list[LogLine]) -> list[StackTrace]:
    """Scan log lines and pull out every complete stack trace."""
    texts = [line.text for line in lines]
    traces: list[StackTrace] = []
    i = 0
    while i < len(texts):
        consumed, trace = _try_parse(texts, i)
        if trace:
            # Stamp with the last line of the trace: the exception line is
            # logged after the request failed, which is what we correlate on.
            end = min(i + max(consumed, 1) - 1, len(lines) - 1)
            trace.timestamp = lines[end].timestamp
            traces.append(trace)
            i += max(consumed, 1)
        else:
            i += 1
    return traces


def _try_parse(texts: list[str], start: int) -> tuple[int, StackTrace | None]:
    line = texts[start]

    if "Traceback (most recent call last)" in line:
        return _parse_python(texts, start)
    if _GO_PANIC.match(line):
        return _parse_go(texts, start)
    # Java/Node traces begin with the exception line itself, followed by "at ".
    if start + 1 < len(texts):
        nxt = texts[start + 1]
        if _JAVA_FRAME.match(nxt) and _JAVA_EXC.match(line):
            return _parse_java(texts, start)
        if _JS_FRAME.match(nxt) and _JS_EXC.match(line):
            return _parse_js(texts, start)
    return 0, None


# Continuation noise between a frame and the next one. Python 3.11+ emits
# caret/tilde markers and "...<N lines>..." elisions under the source line, and
# chained exceptions insert a prose separator.
_PY_CHAIN = (
    "During handling of the above exception, another exception occurred:",
    "The above exception was the direct cause of the following exception:",
)


def _is_python_continuation(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return True
    if stripped in _PY_CHAIN:
        return True
    if stripped.startswith("...") and stripped.endswith("..."):
        return True
    # Caret/tilde underline markers, e.g. "^^^^^" or "~~~~~^^^^".
    if set(stripped) <= set("^~ "):
        return True
    # Any indented line that is not itself a frame is the source snippet.
    return text.startswith((" ", "\t"))


def _chain_continues(texts: list[str], index: int) -> bool:
    """True if a chained-exception separator and another Traceback follow."""
    seen_separator = False
    # The separator and header sit within a few lines of the exception.
    for text in texts[index : index + 4]:
        stripped = text.strip()
        if not stripped:
            continue
        if stripped in _PY_CHAIN:
            seen_separator = True
            continue
        if seen_separator and "Traceback (most recent call last)" in stripped:
            return True
        if not seen_separator:
            return False
    return False


def _parse_python(texts: list[str], start: int) -> tuple[int, StackTrace | None]:
    frames: list[Frame] = []
    i = start + 1
    while i < len(texts):
        match = _PY_FRAME.match(texts[i])
        if match:
            frames.append(
                Frame(match["file"], int(match["line"]), match["func"].strip())
            )
            i += 1
            continue

        # A nested "Traceback" header belongs to a chained exception; keep going
        # so the frames accumulate into one trace rather than fragmenting.
        if "Traceback (most recent call last)" in texts[i]:
            i += 1
            continue

        exc = _PY_EXC.match(texts[i].strip())
        # The exception line is flush-left; indented text is still frame detail.
        if exc and not texts[i].startswith((" ", "\t")):
            # A chained exception follows a "During handling..." separator and
            # another Traceback header. The *last* exception in the chain is the
            # one that actually surfaced, so keep scanning and let it win rather
            # than reporting each link as a separate bug.
            if _chain_continues(texts, i + 1):
                frames = []  # the outer exception's frames supersede these
                i += 1
                continue
            return i + 1 - start, StackTrace(
                language="python",
                exception_type=exc["type"],
                message=(exc["msg"] or "").strip(),
                frames=frames,
                raw="\n".join(texts[start : i + 1]),
            )

        if _is_python_continuation(texts[i]):
            i += 1
            continue
        break

    if frames:
        return i - start, StackTrace(
            "python", "UnknownError", "", frames, "\n".join(texts[start:i])
        )
    return 0, None


def _parse_js(texts: list[str], start: int) -> tuple[int, StackTrace | None]:
    exc = _JS_EXC.match(texts[start])
    if not exc:
        return 0, None
    frames: list[Frame] = []
    i = start + 1
    while i < len(texts):
        match = _JS_FRAME.match(texts[i])
        if not match:
            break
        frames.append(
            Frame(match["file"], int(match["line"]), (match["func"] or "").strip())
        )
        i += 1
    if not frames:
        return 0, None
    return i - start, StackTrace(
        "javascript", exc["type"], exc["msg"].strip(), frames, "\n".join(texts[start:i])
    )


def _parse_java(texts: list[str], start: int) -> tuple[int, StackTrace | None]:
    exc = _JAVA_EXC.match(texts[start])
    if not exc:
        return 0, None
    frames: list[Frame] = []
    i = start + 1
    while i < len(texts):
        match = _JAVA_FRAME.match(texts[i])
        if not match:
            break
        frames.append(
            Frame(
                match["file"],
                int(match["line"]) if match["line"] else None,
                match["func"],
            )
        )
        i += 1
    if not frames:
        return 0, None
    return i - start, StackTrace(
        "java", exc["type"], exc["msg"].strip(), frames, "\n".join(texts[start:i])
    )


def _parse_go(texts: list[str], start: int) -> tuple[int, StackTrace | None]:
    panic = _GO_PANIC.match(texts[start])
    if not panic:
        return 0, None
    frames: list[Frame] = []
    i = start + 1
    while i < len(texts) and i < start + 60:
        match = _GO_FRAME.match(texts[i])
        if match:
            frames.append(Frame(match["file"], int(match["line"]), ""))
        elif frames and not texts[i].startswith(("\t", " ", "goroutine")):
            break
        i += 1
    return i - start, StackTrace(
        "go", "panic", panic["msg"].strip(), frames, "\n".join(texts[start:i])
    )
