"""`autoqa-fix`: propose patches for findings, verify them, report honestly.

Never modifies the working tree. Patches land in an output directory as `.patch`
files plus a summary, and each one has already been applied-and-tested in a
scratch copy before it is offered.
"""

from __future__ import annotations

import argparse
import difflib
import sys
import tempfile
from pathlib import Path

from autoqa.fix.llm import LLMConfig, LLMError, OllamaClient, find_api_key, key_hint
from autoqa.fix.patcher import Candidate, PatchError, propose
from autoqa.fix.verify import (
    Verdict,
    Verifier,
    VerifyResult,
    default_test_command,
    load_report,
)

# Findings worth spending a model call on. Anything less severe is usually a
# validation nicety where a human should decide the intended behaviour.
_DEFAULT_MIN_SEVERITY = "high"
_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="autoqa-fix",
        description=(
            "Propose and verify fixes for AutoQA findings. Writes patches to a "
            "directory; never edits your working tree."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""setup:
  # the key is read from the environment, never passed as a flag
  $env:OLLAMA_API_KEY = "<your key>"        # PowerShell
  export OLLAMA_API_KEY="<your key>"        # bash

example:
  autoqa --spec openapi.json --url http://127.0.0.1:8099 \\
         --launch "python -m uvicorn examples.vulnerable_api.app:app --port 8099" \\
         --health /health --json report.json

  autoqa-fix --report report.json \\
             --launch "python -m uvicorn examples.vulnerable_api.app:app --port {port}" \\
             --health /health
""",
    )
    parser.add_argument("--report", required=True, help="JSON report from a campaign")
    parser.add_argument(
        "--launch", required=True,
        help="command to start the patched target; {port} is substituted",
    )
    parser.add_argument("--health", default="/health", help="health path (default: /health)")
    parser.add_argument(
        "--repo", default=".", help="repository root containing the culprit sources"
    )
    parser.add_argument(
        "--out", default="patches", help="directory for proposed patches (default: patches/)"
    )
    parser.add_argument("--model", default=None, help="Ollama model (env: OLLAMA_MODEL)")
    parser.add_argument(
        "--llm-base-url", default=None,
        help="Ollama endpoint (env: OLLAMA_BASE_URL, default: https://ollama.com)",
    )
    parser.add_argument(
        "--min-severity", choices=list(_RANK), default=_DEFAULT_MIN_SEVERITY,
        help=f"skip findings less severe than this (default: {_DEFAULT_MIN_SEVERITY})",
    )
    parser.add_argument(
        "--max-findings", type=int, default=5,
        help="cap model calls per run (default: 5)",
    )
    parser.add_argument(
        "--test-command", default=None,
        help=f"suite to run in the patched copy (default: {default_test_command()!r}); "
             f"pass '' to skip",
    )
    parser.add_argument(
        "--check-key", action="store_true",
        help="verify the API key and model are reachable, then exit",
    )
    return parser


def _eligible(clusters: list[dict], min_severity: str, limit: int) -> list[dict]:
    threshold = _RANK[min_severity]
    out = []
    for cluster in clusters:
        if _RANK.get(cluster.get("severity", "info"), 4) > threshold:
            continue
        # No stack trace means no located code, so there is nothing to patch.
        if not (cluster.get("stack_trace") or {}).get("culprit"):
            continue
        out.append(cluster)
    out.sort(key=lambda c: _RANK.get(c.get("severity", "info"), 4))
    return out[:limit]


def _diff(candidate: Candidate, repo_root: Path) -> str:
    relative = candidate.file.resolve().relative_to(repo_root.resolve())
    return "".join(
        difflib.unified_diff(
            candidate.original.splitlines(keepends=True),
            candidate.replacement.splitlines(keepends=True),
            fromfile=f"a/{relative.as_posix()}",
            tofile=f"b/{relative.as_posix()}",
            n=3,
        )
    )


_ICON = {
    Verdict.FIXED: "OK  ",
    Verdict.STILL_BROKEN: "NO  ",
    Verdict.BROKE_TESTS: "REG ",
    Verdict.UNVERIFIABLE: "??  ",
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not find_api_key():
        print(f"error: {key_hint()}", file=sys.stderr)
        return 2

    config = LLMConfig.from_env(model=args.model, base_url=args.llm_base_url)
    try:
        client = OllamaClient(config)
    except LLMError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.check_key:
        print(f"  endpoint {config.base_url}")
        print(f"  model    {config.model}")
        try:
            reply = client.complete("Reply with the single word: ready", "ready?")
        except LLMError as exc:
            print(f"  FAILED   {exc}", file=sys.stderr)
            return 2
        print(f"  reply    {reply.strip()[:60]!r}")
        print("  key and model are reachable.")
        return 0

    report_path = Path(args.report)
    if not report_path.exists():
        print(f"error: report not found: {report_path}", file=sys.stderr)
        return 2
    try:
        clusters = load_report(report_path)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    repo_root = Path(args.repo).resolve()
    targets = _eligible(clusters, args.min_severity, args.max_findings)
    if not targets:
        print(
            f"  no eligible findings in {report_path}.\n"
            f"  Needs severity >= {args.min_severity} AND a server-side stack trace.\n"
            f"  Re-run the campaign with --launch so traces are captured."
        )
        return 0

    test_command = (
        default_test_command() if args.test_command is None else args.test_command
    )
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"  {len(targets)} finding(s) eligible; model {config.model}")
    print(f"  patches -> {out_dir}/   (working tree is never modified)")
    print()

    results: list[VerifyResult] = []
    skipped: list[tuple[str, str]] = []

    with tempfile.TemporaryDirectory(prefix="autoqa-fix-") as scratch:
        verifier = Verifier(
            repo_root, Path(scratch),
            launch_command=args.launch,
            health_path=args.health,
            test_command=test_command or None,
        )

        for index, finding in enumerate(targets, start=1):
            title = finding.get("title", "?")
            print(f"  [{index}/{len(targets)}] {title[:66]}")
            try:
                candidate = propose(finding, client, repo_root)
            except PatchError as exc:
                print(f"           skipped: {exc}")
                skipped.append((title, str(exc)))
                continue

            result = verifier.verify(candidate, finding)
            results.append(result)
            print(f"           {_ICON[result.verdict]}{result.detail}")

            patch_text = _diff(candidate, repo_root)
            name = f"{result.verdict.value}-{candidate.signature[:16]}.patch"
            (out_dir / name).write_text(
                f"# {title}\n"
                f"# verdict: {result.verdict.value} — {result.detail}\n"
                f"# proposed by {config.model} via {config.base_url}\n"
                f"# NOT APPLIED. Review, then: git apply {out_dir / name}\n"
                f"{patch_text}",
                encoding="utf-8",
            )

    accepted = [r for r in results if r.accepted]
    print()
    print("  " + "-" * 68)
    print(f"  proposed {len(results)}  accepted {len(accepted)}  "
          f"rejected {len(results) - len(accepted)}  skipped {len(skipped)}")
    if accepted:
        print()
        print("  Verified fixes (bug gone, suite still green):")
        for result in accepted:
            print(f"    {out_dir / f'fixed-{result.candidate.signature[:16]}.patch'}")
        print()
        print("  These were tested in a scratch copy, not reviewed. Read the diff")
        print("  before applying: git apply <patch>")
    elif results:
        print()
        print("  Nothing verified clean. The rejected patches are still in")
        print(f"  {out_dir}/ and may point at the right area even so.")

    # A run that proposed nothing usable is not a failure of the tool.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
