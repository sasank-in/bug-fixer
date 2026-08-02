# AutoQA

An autonomous QA engineer for HTTP APIs. Point it at an OpenAPI spec and a
running service; it generates schema-aware requests, mutates them into hostile
variants, watches the server's logs while it does so, and reports the distinct
bugs it found with a copy-pasteable reproducer for each.

```
  FINDINGS      17 distinct issues  (critical:9  high:5  medium:3)
                from 65 raw observations

!! [2] Valid request fails with 500 on POST /transfer
     severity   critical
     seen       8x across 1 operation(s)
     triggers   deep_nesting, unknown_field

     root cause KeyError: 'from'
     at         examples/vulnerable_api/app.py:73 in transfer

     repro:
       curl -i -X POST http://127.0.0.1:8099/transfer \
         -H 'Content-Type: application/json' -d '{}'
```

## Install

```bash
pip install -e ".[dev,demo]"
```

## Use

Against a service that's already running:

```bash
autoqa --spec openapi.json --url http://localhost:8000
```

Let AutoQA launch the target too. This is the mode you want — it tails the
process's stdout/stderr, so findings come with the server-side stack trace and
the exact line that raised:

```bash
autoqa --spec openapi.json --url http://localhost:8000 \
       --launch "uvicorn app:app --port 8000" --health /health
```

In CI, with reports and a failure threshold:

```bash
autoqa --spec openapi.json --url http://localhost:8000 \
       --cases 100 --md report.md --json report.json --fail-on high
```

### Options that matter

| Flag | Why you'd use it |
| --- | --- |
| `--cases N` | Mutated requests per operation. 25 is a smoke test; 100+ is a real hunt. |
| `--seed N` | Every run is deterministic. Reuse the seed from a report to replay it exactly. |
| `--launch CMD` | Captures server logs. Without it you get status codes but no root causes. |
| `--auth 'Authorization: Bearer …'` | Sent with every request. |
| `--include` / `--exclude` | Substring match on `METHOD /path`, repeatable. |
| `--rate-limit N` | Requests per second, for targets you shouldn't hammer. |
| `--fail-on SEVERITY` | Exit non-zero when something at least this bad is found. |

## How it works

```
OpenAPI spec ──▶ operations ──▶ valid baseline request
                                        │
                                        ▼
                                 one mutation applied
                                        │
                    ┌───────────────────┴──────────────────┐
                    ▼                                      ▼
             HTTP executor                        target process
          (async, bounded)                    (stdout/stderr tailed)
                    │                                      │
                    └──────────────┬───────────────────────┘
                                   ▼
                          oracles decide "bug?"
                                   ▼
                     cluster by root cause + operation
                                   ▼
                       minimize each exemplar
                                   ▼
                    terminal / Markdown / JSON report
```

**One mutation per request.** A request carries exactly one deliberate defect,
so when it fails there's no ambiguity about which change caused it.

**Oracles, not status codes.** A 400 on garbage input is correct behaviour and
is not reported. What gets reported: 5xx responses, connection failures and
hangs, internal detail leaking into response bodies (stack traces, SQL errors,
filesystem paths, secrets), payloads that were *evaluated* rather than echoed,
schema-violating input accepted with a 2xx, and latency outliers measured
against each operation's own median.

**Clustering is the point.** A fuzzer hits the same bug hundreds of times. Runs
here typically collapse ~65 raw observations into ~17 real issues, keyed on the
server-side stack trace where one is available and a normalized error
fingerprint otherwise. Two rules keep the output honest: the offending *value*
is normalized out (so `'a.txt'` and `'../../etc/passwd'` are one bug), and the
operation is always part of the key (so one shared helper failing on two
endpoints never merges into a report whose title and reproducer disagree).

**Minimization.** Each cluster's exemplar is delta-debugged against the live
target until it's the smallest request that still fails the same way. Transport
failures are deliberately skipped — with no status and no body, "same failure"
can't be verified, and a shrunk repro that doesn't reproduce is worse than none.

## Try it

A deliberately buggy API ships with the repo:

```bash
python -c "import json;from examples.vulnerable_api.app import app;print(json.dumps(app.openapi()))" > openapi.json

autoqa --spec openapi.json --url http://127.0.0.1:8099 \
       --launch "python -m uvicorn examples.vulnerable_api.app:app --port 8099 --log-level warning" \
       --health /health --cases 20
```

It has ten planted defects — SQL injection, unchecked `None`, division by zero,
`KeyError` on missing fields, template evaluation, path traversal, unbounded
work. AutoQA finds them and names the line for each.

## Tests

```bash
pytest              # 89 tests
pytest -q -k e2e    # end-to-end: fuzzes the demo API and asserts on findings
```

The e2e suite is the meaningful one. It runs a real campaign and asserts the
invariants that make a report trustworthy: traces attach to the operation that
produced them, no cluster spans two operations, titles agree with their
reproducers, and no culprit frame ever points into a dependency.

## Layout

```
autoqa/
  spec/parser.py       OpenAPI 3.x → operations, with $ref resolution
  fuzz/generators.py   JSON Schema → conforming values
  fuzz/mutators.py     conforming value → hostile variant
  fuzz/engine.py       operations → concrete test cases
  runner/executor.py   async HTTP with bounded concurrency
  runner/process.py    launches the target, tails its output
  analysis/traces.py   log text → stack traces (Python/JS/Java/Go)
  analysis/oracles.py  response → findings
  analysis/cluster.py  findings → distinct issues
  analysis/minimizer.py delta-debugging to a minimal repro
  report/render.py     terminal, Markdown, JSON
  campaign.py          orchestration
  cli.py               entry point
```

## Supported

Targets: any HTTP service with an OpenAPI 3.x spec (JSON or YAML).
Stack traces: Python (including 3.11+ caret markers and chained exceptions),
Node/JS, Java/JVM, Go panics.

## Not built yet

From the original brief, what's deliberately still open:

- **Proposes fixes / opens pull requests.** Deferred on purpose. The
  deterministic core had to be trustworthy first — an LLM patch layer on top of
  noisy findings just produces confident wrong diffs. The JSON report is shaped
  to be its input: each cluster carries the culprit frame, the minimized repro,
  and the evidence.
- **Coverage-guided mutation.** Mutation is schema-aware but blind to which code
  paths it reached. Feedback from `coverage.py` would let it steer.
- **Stateful sequences.** Each request is independent, so bugs that need
  create-then-read-then-delete ordering aren't reachable yet.
