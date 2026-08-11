# AutoQA

An autonomous QA engineer for HTTP APIs. Point it at an OpenAPI spec and a
running service; it generates schema-aware requests, mutates them into hostile
variants, watches the server's logs while it does so, and reports the distinct
bugs it found with a copy-pasteable reproducer for each.

```
  FINDINGS      16 distinct issues  (critical:9  high:4  medium:3)
                from 61 raw observations

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

Status: the fuzz → observe → analyse → report loop works end to end. Proposing
fixes and opening pull requests is [not built yet](#not-built-yet).

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

Run `autoqa --help` for the full list.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Ran to completion. Findings may still exist — pass `--fail-on` to gate on them. |
| `1` | A finding met or exceeded the `--fail-on` threshold. |
| `2` | Setup failed: spec missing or unparseable, target never became ready, bad arguments. |
| `130` | Interrupted (Ctrl-C). |

Note the difference between `1` and `2`: `1` means the tool worked and your API
has a bug; `2` means the tool never got to test anything.

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
pytest                     # 150 tests, ~4s
pytest tests/test_e2e.py   # end-to-end: fuzzes the demo API, asserts on findings
```

The e2e suite is the meaningful one. It runs a real campaign and asserts the
invariants that make a report trustworthy: traces attach to the operation that
produced them, no cluster spans two operations, titles agree with their
reproducers, no culprit frame points into a dependency, and the curl reproducer
encodes byte-for-byte the way the request was actually sent.

## Layout

```
autoqa/
  spec/parser.py         OpenAPI 3.x → operations, with $ref resolution
  fuzz/generators.py     JSON Schema → conforming values
  fuzz/mutators.py       conforming value → hostile variant
  fuzz/engine.py         operations → concrete test cases
  runner/http.py         shared encoding, so requests and repros cannot drift
  runner/executor.py     async HTTP with bounded concurrency
  runner/process.py      launches the target, tails its output
  analysis/traces.py     log text → stack traces (Python/JS/Java/Go)
  analysis/oracles.py    response → findings
  analysis/normalize.py  shared "is this the same error?" text reduction
  analysis/cluster.py    findings → distinct issues
  analysis/minimizer.py  delta-debugging to a minimal repro
  report/render.py       terminal, Markdown, JSON
  campaign.py            orchestration
  cli.py                 entry point
```

## Supported

Targets: any HTTP service with an OpenAPI 3.x spec (JSON or YAML).
Stack traces: Python (including 3.11+ caret markers and chained exceptions),
Node/JS, Java/JVM, Go panics.

## Known limitations

Worth knowing before you trust a clean run:

**Security oracles are probabilistic, not guaranteed.** Hostile payloads are
sampled at random, so any *specific* one — the `{{7*7}}` that proves template
injection, say — reaches a given parameter with probability ~`1/22` per mutation
of that parameter. In practice:

| `--cases` | Chance a given payload is ever sent to one query param |
| --- | --- |
| 20 | ~37% |
| 50 | ~68% |
| 100 | ~90% |
| 200 | ~99% |

Crash-hunting doesn't care (any garbage triggers a `KeyError`), but injection
detection does. **A clean run at `--cases 20` is weak evidence about injection**;
use 100+ when that's what you're checking. A deterministic payload sweep that
sends every security payload to every string parameter exactly once would make
this a guarantee — that's the next thing worth building.

**Traces need the target's stderr.** Without `--launch`, findings carry status
codes and response bodies but no culprit line. Handlers that catch their own
exceptions log nothing, so those get no trace either — correctly, since there's
nothing to attribute.

**Attribution is conservative.** Under concurrency, overlapping requests make
some traces ambiguous; those are left unattributed rather than guessed at. You
will see findings without a root cause even when the target did log one.

**Requests are independent.** No bug requiring an ordered sequence
(create → delete → read) is reachable.

## Not built yet

From the original brief, what's deliberately still open, roughly in the order
worth doing:

1. **Deterministic payload sweep.** Send every security payload to every string
   parameter exactly once, alongside the random mutation. Bounded cost, and it
   turns the probability table above into a guarantee.
2. **Stateful sequences.** Infer resource links (`POST /orders` →
   `GET /orders/{id}`) and fuzz the sequence, not the call. This is the largest
   capability gain — use-after-delete, broken pagination, and IDOR all live here.
3. **Coverage-guided mutation.** Feedback from `coverage.py` would let mutation
   steer toward unexplored branches instead of re-hitting the same handler.
   Powerful, but only when the target is Python and runnable under coverage.
4. **Proposes fixes / opens pull requests.** Deferred on purpose: the
   deterministic core had to be trustworthy first, since an LLM patch layer on
   top of noisy findings just produces confident wrong diffs. It also needs a
   way to *verify* a fix, which is really item 2. The JSON report is already
   shaped as its input — each cluster carries the culprit frame, the minimized
   reproducer, and the evidence.

## Development

```bash
pip install -e ".[dev,demo]"
pytest -q                              # 150 tests, ~4s
ruff check autoqa/ tests/ examples/    # lint
```

Using conda, run through the environment explicitly so the launched target lands
in the same interpreter as the fuzzer:

```bash
conda run -n base --no-capture-output pytest -q
conda run -n base --no-capture-output python -m autoqa.cli --spec … --url …
```

`--launch` inherits whatever `python` resolves to on `PATH`. If that is a
different environment than the one running AutoQA, the target will fail to
import its own dependencies and the run aborts with "target did not become
ready" — pass an absolute interpreter path in `--launch` if the two can differ.

CI runs lint and tests on Python 3.10 and 3.13 (the trace parser is
version-sensitive), then dogfoods the tool against the demo API and fails if it
stops finding the planted bugs. See [CONTRIBUTING.md](CONTRIBUTING.md) for the
design rules and the encoding traps that have already caused bugs.
