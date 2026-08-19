"""Turn a confirmed finding into a proposed source patch.

The model is given exactly three things: the culprit source (a window around the
frame the stack trace named), the reproducer, and the observed failure. It is
asked for a full replacement of that window, not a diff — models are markedly
worse at emitting valid unified diffs than at rewriting a function, and a
malformed diff is unrecoverable while a rewritten window is easy to validate.

Nothing here trusts the reply. `propose` only produces a candidate; deciding
whether it is correct is `verify.py`'s job, and that decision is made by running
the reproducer and the test suite, not by reading the patch.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

from autoqa.fix.llm import LLMError, OllamaClient

# Lines of source either side of the culprit line. Enough for the function plus
# its in-scope context, small enough to keep a 7B model on task.
CONTEXT_BEFORE = 40
CONTEXT_AFTER = 40

SYSTEM_PROMPT = """You are a precise software engineer fixing one bug in Python code.

Rules:
1. Output ONLY the corrected code block, wrapped in ```python fences. No prose.
2. Reproduce the code you were given, line for line, EXCEPT for the minimal
   change that fixes the described bug.
3. Preserve the exact original indentation. The snippet is an excerpt from a
   larger file and must drop back in unchanged apart from your fix.
4. Do not rename anything, change signatures, add imports, or reformat.
5. Fix the root cause. Do not wrap the whole body in try/except to hide it.
6. Invalid input should be rejected with an explicit 4xx error, not crash.
If you cannot fix it from what you were given, output exactly: CANNOT_FIX
"""


@dataclass
class Candidate:
    """A proposed edit to one region of one file."""

    signature: str
    file: Path
    start_line: int          # 1-indexed, inclusive
    end_line: int            # 1-indexed, inclusive
    original: str
    replacement: str
    rationale: str = ""

    @property
    def is_noop(self) -> bool:
        return self.original.strip() == self.replacement.strip()

    def apply_to(self, text: str) -> str:
        """Splice the replacement into `text` at the recorded line range."""
        lines = text.splitlines(keepends=True)
        head = "".join(lines[: self.start_line - 1])
        tail = "".join(lines[self.end_line :])
        body = self.replacement
        if not body.endswith("\n"):
            body += "\n"
        return head + body + tail


class PatchError(RuntimeError):
    """Raised when no usable candidate can be produced."""


def enclosing_block(source: str, line: int) -> tuple[int, int] | None:
    """Line range of the smallest function or class containing `line`.

    Scoping the patch window to a real syntactic unit matters for correctness,
    not just tidiness. A fixed line window around the culprit can span the whole
    file on a short module, and a model that replies with only the function then
    silently deletes the imports above it — which fails at import time with a
    confusing NameError rather than as an obviously bad patch.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    best: tuple[int, int] | None = None
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        start = min(
            [node.lineno] + [d.lineno for d in node.decorator_list]
        )
        end = getattr(node, "end_lineno", None)
        if end is None or not (start <= line <= end):
            continue
        # Smallest enclosing block wins, so a method beats its class.
        if best is None or (end - start) < (best[1] - best[0]):
            best = (start, end)
    return best


def _read_window(path: Path, line: int) -> tuple[int, int, str]:
    """The source region to hand the model, preferring the enclosing function."""
    source = path.read_text(encoding="utf-8")
    lines = source.splitlines(keepends=True)

    block = enclosing_block(source, line)
    if block is not None:
        start, end = block
    else:
        # No enclosing function (module-level code, or an unparseable file):
        # fall back to a line window, but never let it swallow the file header,
        # since a partial reply would then delete the imports.
        start = max(1, line - CONTEXT_BEFORE)
        end = min(len(lines), line + CONTEXT_AFTER)

    return start, end, "".join(lines[start - 1 : end])


_FENCE = re.compile(r"```(?:python|py)?\s*\n(?P<code>.*?)```", re.S)
# Models sometimes echo the line-number gutter back despite being told not to.
_GUTTER = re.compile(r"^\s*\d+\s*\|\s?")


def strip_gutter(code: str) -> str:
    """Remove `  123| ` prefixes if the model echoed them back.

    Left in place they would be syntax errors, and the whole candidate would be
    thrown away over a formatting slip rather than a wrong fix.
    """
    lines = code.splitlines()
    if not lines:
        return code
    matched = sum(1 for line in lines if _GUTTER.match(line))
    # Only strip when it is clearly the gutter pattern, not an incidental match.
    if matched < max(2, len(lines) // 2):
        return code
    return "\n".join(_GUTTER.sub("", line) for line in lines)


def extract_code(reply: str) -> str:
    """Pull the code block out of a model reply.

    Models add prose despite instructions, and sometimes emit several blocks.
    The longest fenced block is the intended answer; an unfenced reply is
    accepted only if it parses as Python, so stray prose cannot become source.
    """
    if "CANNOT_FIX" in reply:
        raise PatchError("model declined to propose a fix")

    blocks = [m.group("code") for m in _FENCE.finditer(reply)]
    if blocks:
        return strip_gutter(max(blocks, key=len).rstrip()) + "\n"

    stripped = strip_gutter(reply.strip())
    if not stripped:
        raise PatchError("empty reply")
    try:
        ast.parse(_dedent_for_parse(stripped))
    except SyntaxError as exc:
        raise PatchError(
            f"reply was neither a fenced code block nor valid Python: {exc}"
        ) from exc
    return stripped + "\n"


def _dedent_for_parse(code: str) -> str:
    """Left-strip a uniformly indented snippet so `ast.parse` accepts it."""
    lines = [line for line in code.splitlines() if line.strip()]
    if not lines:
        return code
    indent = min(len(line) - len(line.lstrip()) for line in lines)
    if indent == 0:
        return code
    return "\n".join(
        line[indent:] if len(line) >= indent else line for line in code.splitlines()
    )


def validate_syntax(candidate: Candidate) -> None:
    """Reject a candidate that would not even parse in place.

    Cheap gate before spending a test run: splice the replacement into the real
    file contents and parse the whole module. A snippet can look fine alone and
    still break the file it lands in — mismatched indentation being the usual
    way.
    """
    source = candidate.file.read_text(encoding="utf-8")
    patched = candidate.apply_to(source)
    try:
        patched_tree = ast.parse(patched)
    except SyntaxError as exc:
        raise PatchError(
            f"patch does not parse in place at {candidate.file.name}:"
            f"{exc.lineno}: {exc.msg}"
        ) from exc

    # A patch must never make top-level definitions disappear. A model that
    # replies with just the buggy function, when the window covered more, would
    # otherwise silently delete imports or sibling functions — which surfaces as
    # a baffling NameError at import time instead of an obviously bad patch.
    try:
        before = _toplevel_names(ast.parse(source))
    except SyntaxError:
        return  # cannot compare against a file that was already broken
    lost = before - _toplevel_names(patched_tree)
    if lost:
        raise PatchError(
            f"patch would remove top-level definitions from "
            f"{candidate.file.name}: {', '.join(sorted(lost))}. The reply "
            f"probably covered less code than the window it replaces."
        )


def _toplevel_names(tree: ast.Module) -> set[str]:
    """Names a module defines or imports at the top level."""
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                names.add(alias.asname or alias.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
    return names


def build_prompt(
    *,
    title: str,
    detail: str,
    reproducer: str,
    observed: str,
    exception: str,
    culprit: str,
    code: str,
    start_line: int,
) -> str:
    numbered = "\n".join(
        f"{start_line + i:5d}| {line}" for i, line in enumerate(code.splitlines())
    )
    last_line = start_line + len(code.splitlines()) - 1
    return f"""A fuzzer found this bug.

FINDING: {title}
{detail}

REPRODUCER:
{reproducer}

OBSERVED: {observed}
EXCEPTION: {exception or "(none captured)"}
CULPRIT FRAME: {culprit}

The code below is lines {start_line}-{last_line} of that file. Line numbers are
shown for reference only — do NOT include them in your output.

```python
{numbered}
```

Return the same lines with the bug fixed, in a ```python block, without the
line-number prefixes."""


def locate_culprit(finding: dict, repo_root: Path) -> tuple[Path, int, str]:
    """Resolve a finding's culprit frame to a file and line inside the repo."""
    trace = finding.get("stack_trace") or {}
    culprit = trace.get("culprit")
    if not culprit:
        raise PatchError(
            "no culprit frame — the finding has no server-side stack trace, so "
            "there is no located code to patch"
        )

    # A culprit reads "path:line in func".
    location = culprit.split(" in ")[0]
    raw_path, _, raw_line = location.rpartition(":")
    if not raw_path or not raw_line.isdigit():
        raise PatchError(f"could not parse culprit frame {culprit!r}")

    path = Path(raw_path)
    if not path.is_absolute():
        path = repo_root / path
    if not path.exists():
        raise PatchError(f"culprit file not found: {path}")

    # Never edit outside the repository. A trace can legitimately point into
    # site-packages, and rewriting a dependency would be both wrong and
    # invisible to review.
    try:
        path.resolve().relative_to(repo_root.resolve())
    except ValueError:
        raise PatchError(
            f"culprit file {path} is outside the repository; refusing to patch "
            f"dependency or system code"
        ) from None

    if path.suffix != ".py":
        raise PatchError(
            f"only Python sources are supported, got "
            f"{path.suffix or 'no extension'}"
        )
    return path, int(raw_line), culprit


def propose(finding: dict, client: OllamaClient, repo_root: Path) -> Candidate:
    """Ask the model for a fix to one report cluster.

    `finding` is a cluster dict from the JSON report.
    """
    path, line, culprit = locate_culprit(finding, repo_root)
    start, end, window = _read_window(path, line)

    trace = finding.get("stack_trace") or {}
    observed = finding.get("observed") or {}
    prompt = build_prompt(
        title=finding.get("title", ""),
        detail=finding.get("detail", ""),
        reproducer=(finding.get("reproducer") or {}).get("curl", ""),
        observed=(
            f"HTTP {observed.get('status')}"
            if observed.get("status")
            else str(observed.get("transport_error"))
        ),
        exception=(
            f"{trace.get('exception_type', '')}: {trace.get('message', '')}".strip(": ")
        ),
        culprit=culprit,
        code=window,
        start_line=start,
    )

    try:
        reply = client.complete(SYSTEM_PROMPT, prompt)
    except LLMError as exc:
        raise PatchError(str(exc)) from exc

    candidate = Candidate(
        signature=finding.get("signature", "unknown"),
        file=path,
        start_line=start,
        end_line=end,
        original=window,
        replacement=extract_code(reply),
        rationale=finding.get("title", ""),
    )
    if candidate.is_noop:
        raise PatchError("model returned the original code unchanged")
    validate_syntax(candidate)
    return candidate
