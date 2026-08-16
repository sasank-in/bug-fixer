"""Command-line entry point for AutoQA."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from autoqa.analysis.oracles import Severity
from autoqa.campaign import Campaign, CampaignConfig
from autoqa.report.render import render_json, render_markdown, render_terminal

_SEVERITY_CHOICES = [s.value for s in Severity]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="autoqa",
        description="Autonomous API fuzzing: mutate inputs, trace failures, report bugs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  # fuzz an already-running service
  autoqa --spec openapi.json --url http://localhost:8000

  # launch the target too, so server-side stack traces get captured
  autoqa --spec openapi.json --url http://localhost:8000 \\
         --launch "python -m uvicorn app:app --port 8000" --health /health

  # deeper run, write reports, fail CI on anything high or worse
  autoqa --spec openapi.json --url http://localhost:8000 \\
         --cases 100 --md report.md --json report.json --fail-on high
""",
    )
    parser.add_argument("--spec", required=True, help="path to an OpenAPI 3.x JSON/YAML file")
    parser.add_argument("--url", required=True, help="base URL of the running target")
    parser.add_argument(
        "--cases", type=int, default=25, help="mutated cases per operation (default: 25)"
    )
    parser.add_argument("--seed", type=int, default=1337, help="RNG seed (default: 1337)")
    parser.add_argument(
        "--concurrency", type=int, default=8, help="parallel in-flight requests (default: 8)"
    )
    parser.add_argument(
        "--timeout", type=float, default=10.0, help="per-request timeout seconds (default: 10)"
    )
    parser.add_argument(
        "--rate-limit", type=float, default=None,
        help="cap requests per second (default: unlimited)",
    )
    parser.add_argument(
        "--launch", default=None,
        help="command to start the target; enables log capture and stack traces",
    )
    parser.add_argument("--launch-cwd", default=None, help="working directory for --launch")
    parser.add_argument(
        "--health", default="/", help="health path polled after --launch (default: /)"
    )
    parser.add_argument(
        "--auth", default=None,
        help="auth header as 'Name: value', e.g. 'Authorization: Bearer xyz'",
    )
    parser.add_argument(
        "--include", action="append", default=[],
        help="only fuzz operations whose 'METHOD /path' contains this (repeatable)",
    )
    parser.add_argument(
        "--exclude", action="append", default=[],
        help="skip operations whose 'METHOD /path' contains this (repeatable)",
    )
    parser.add_argument(
        "--no-minimize", action="store_true",
        help="skip reproducer minimization (faster, less actionable output)",
    )
    parser.add_argument(
        "--no-sequences", action="store_true",
        help=(
            "skip stateful sequence fuzzing; use-after-delete and "
            "non-idempotent transitions then go unreachable"
        ),
    )
    parser.add_argument(
        "--no-security-sweep", action="store_true",
        help=(
            "skip the deterministic security probes; injection coverage then "
            "depends on --cases and is no longer guaranteed"
        ),
    )
    parser.add_argument("--md", default=None, help="write a Markdown report to this path")
    parser.add_argument("--json", dest="json_out", default=None, help="write a JSON report")
    parser.add_argument(
        "--fail-on", choices=_SEVERITY_CHOICES, default=None,
        help="exit non-zero if any finding is at least this severe",
    )
    parser.add_argument("--quiet", action="store_true", help="suppress progress output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    auth: tuple[str, str] | None = None
    if args.auth:
        if ":" not in args.auth:
            print("error: --auth must look like 'Name: value'", file=sys.stderr)
            return 2
        name, _, value = args.auth.partition(":")
        auth = (name.strip(), value.strip())

    if not Path(args.spec).exists():
        print(f"error: spec not found: {args.spec}", file=sys.stderr)
        return 2

    config = CampaignConfig(
        spec_path=args.spec,
        base_url=args.url,
        cases_per_operation=args.cases,
        seed=args.seed,
        concurrency=args.concurrency,
        timeout=args.timeout,
        launch_command=args.launch,
        launch_cwd=args.launch_cwd,
        health_path=args.health,
        auth_header=auth,
        include=args.include,
        exclude=args.exclude,
        minimize_findings=not args.no_minimize,
        rate_limit_per_sec=args.rate_limit,
        security_sweep=not args.no_security_sweep,
        stateful_sequences=not args.no_sequences,
    )

    def progress(message: str) -> None:
        if not args.quiet:
            print(f"  · {message}", file=sys.stderr)

    try:
        report = Campaign(config, on_progress=progress).run()
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except Exception as exc:
        # Intentionally broad: setup problems (unreadable spec, target that
        # never starts, bad URL) should print one clear line and exit 2, not
        # dump a traceback at someone running a CLI.
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(render_terminal(report))

    if args.md:
        Path(args.md).write_text(render_markdown(report), encoding="utf-8")
        print(f"  markdown report -> {args.md}", file=sys.stderr)
    if args.json_out:
        Path(args.json_out).write_text(render_json(report), encoding="utf-8")
        print(f"  json report     -> {args.json_out}", file=sys.stderr)

    if args.fail_on:
        threshold = Severity(args.fail_on)
        worst = min(
            (c.severity for c in report.clusters),
            key=lambda s: s.rank,
            default=None,
        )
        if worst is not None and worst.rank <= threshold.rank:
            print(
                f"  failing: found {worst.value} severity (threshold {threshold.value})",
                file=sys.stderr,
            )
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
