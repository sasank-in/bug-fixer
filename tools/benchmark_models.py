"""Pick the default model for `autoqa-fix` by measuring, not by name.

Two things this exists to settle, both learned the hard way:

- The endpoint's catalogue is not an entitlement list. `/api/tags` advertises
  models a given key answers `403 requires a subscription` for, so the usable
  set has to be probed.
- Cloud latency varies enough that a single sample is noise. One model measured
  3s and 38s on the same prompt in two runs, which is the difference between
  first and last place on a one-shot ranking.

So: probe for reachability, then score the reachable models on the demo API's
real bugs, repeated, ranking on criteria met first and median latency second.

    python tools/benchmark_models.py            # probe + score everything usable
    python tools/benchmark_models.py --reps 5   # more samples, less noise
"""

from __future__ import annotations

import argparse
import statistics
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from autoqa.fix.llm import LLMConfig, OllamaClient, find_api_key, key_hint  # noqa: E402
from autoqa.fix.patcher import (  # noqa: E402
    SYSTEM_PROMPT,
    PatchError,
    available_names,
    build_prompt,
    extract_code,
)


@dataclass(frozen=True)
class Task:
    """One real bug, and what a good patch for it must contain."""

    name: str
    code: str
    exception: str
    # Each check is (label, predicate over the returned code).
    criteria: tuple[tuple[str, object], ...]


# Both taken verbatim from examples/vulnerable_api, so a score here reflects
# behaviour on bugs AutoQA genuinely reports.
TASKS: tuple[Task, ...] = (
    Task(
        "sqli+none",
        '@app.get("/users/{user_id}")\n'
        "def get_user(user_id: str) -> Any:\n"
        '    cursor = _db.execute(f"SELECT id, name, role FROM users WHERE id = {user_id}")\n'
        "    row = cursor.fetchone()\n"
        '    return {"id": row[0], "name": row[1], "role": row[2]}\n',
        "TypeError: 'NoneType' object is not subscriptable",
        (
            ("guard", lambda c: "is None" in c or "if not row" in c),
            ("param-sql", lambda c: "?" in c and "execute(" in c),
            ("4xx", lambda c: "404" in c or "400" in c),
            # Reaching for an unimported name is the failure mode that made
            # patches parse cleanly and then NameError at request time.
            ("no-unavailable-name", lambda c: "HTTPException" not in c),
        ),
    ),
    Task(
        "keyerror",
        '@app.post("/transfer")\n'
        "def transfer(payload: dict = Body(...)) -> Any:\n"
        '    source = payload["from"]\n'
        '    dest = payload["to"]\n'
        '    amount = float(payload["amount"])\n'
        '    return {"from": source, "to": dest}\n',
        "KeyError: 'from'",
        (
            ("guard", lambda c: "not in payload" in c or ".get(" in c),
            ("4xx", lambda c: "400" in c or "422" in c),
            ("no-unavailable-name", lambda c: "HTTPException" not in c),
        ),
    ),
)


@dataclass
class Score:
    model: str
    hits: int = 0
    possible: int = 0
    parse_failures: int = 0
    latencies: list[float] = field(default_factory=list)

    @property
    def median(self) -> float:
        return statistics.median(self.latencies) if self.latencies else 0.0

    @property
    def worst(self) -> float:
        return max(self.latencies) if self.latencies else 0.0

    @property
    def rate(self) -> float:
        return self.hits / self.possible if self.possible else 0.0


def score_model(
    model: str, client: OllamaClient, available: list[str], reps: int, timeout: float
) -> Score:
    result = Score(model=model)
    for _ in range(reps):
        for task in TASKS:
            result.possible += len(task.criteria)
            prompt = build_prompt(
                title="HTTP 500",
                detail="Unhandled server error.",
                reproducer="curl -i ...",
                observed="HTTP 500",
                exception=task.exception,
                culprit="examples/vulnerable_api/app.py:46 in handler",
                code=task.code,
                start_line=42,
                available=available,
            )
            started = time.time()
            try:
                reply = client.complete(SYSTEM_PROMPT, prompt)
                result.latencies.append(time.time() - started)
            except Exception:
                # A model that cannot answer scores nothing and is charged the
                # full timeout, so slowness is visible in the ranking.
                result.parse_failures += 1
                result.latencies.append(timeout)
                continue
            try:
                code = extract_code(reply)
            except PatchError:
                result.parse_failures += 1
                continue
            result.hits += sum(1 for _, check in task.criteria if check(code))
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--reps", type=int, default=3, help="samples per task (default: 3)")
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument(
        "--model", action="append", default=[],
        help="only score these (repeatable); default is everything reachable",
    )
    args = parser.parse_args(argv)

    if not find_api_key():
        print(f"error: {key_hint()}", file=sys.stderr)
        return 2

    config = LLMConfig(timeout=args.timeout)
    probe_client = OllamaClient(config)

    if args.model:
        candidates = args.model
    else:
        catalogue = probe_client.list_models()
        print(f"  {len(catalogue)} model(s) advertised; probing reachability...")
        candidates = []
        for name in catalogue:
            status = probe_client.probe(name)
            if status == "ok":
                candidates.append(name)
            else:
                print(f"    --  {name:28} {status}")
        print(f"  {len(candidates)} reachable\n")

    if not candidates:
        print("  no reachable models to score.")
        return 1

    available = available_names(
        (ROOT / "examples" / "vulnerable_api" / "app.py").read_text(encoding="utf-8")
    )

    scores = []
    for model in candidates:
        client = OllamaClient(LLMConfig(model=model, timeout=args.timeout))
        score = score_model(model, client, available, args.reps, args.timeout)
        scores.append(score)
        print(
            f"  {model:24} {score.hits:3}/{score.possible:<3} "
            f"({score.rate:4.0%})  median {score.median:5.1f}s  "
            f"worst {score.worst:5.1f}s  parse-fails {score.parse_failures}",
            flush=True,
        )

    print()
    print("  RANKING (criteria met first, then median latency):")
    for score in sorted(scores, key=lambda s: (-s.rate, s.median)):
        print(f"    {score.model:24} {score.rate:4.0%}  median {score.median:5.1f}s")

    best = min(scores, key=lambda s: (-s.rate, s.median))
    print()
    print(f"  Suggested DEFAULT_MODEL in autoqa/fix/llm.py: {best.model!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
