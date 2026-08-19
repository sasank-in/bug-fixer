# AutoQA

An autonomous QA engineer for HTTP APIs. Point it at an OpenAPI spec and a
running service; it generates schema-aware requests, mutates them into hostile
variants, watches the server's logs while it does so, and reports the distinct
bugs it found with a copy-pasteable reproducer for each.

```
  FINDINGS      14 distinct issues  (critical:5  high:6  medium:3)
                from 58 raw observations

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

Status: the fuzz → observe → analyse → report loop works end to end, and
`autoqa-fix` proposes verified patches for findings. Opening pull requests
automatically is [not built yet](#not-built-yet).

## Install

```bash
pip install -e ".[dev,demo]"      # recommended: reads pyproject.toml
```

Requirements files are provided for environments that expect them:

```bash
pip install -r requirements.txt        # runtime only — enough to run the CLI
pip install -r requirements-dev.txt    # adds tests, lint, and the demo API
```

`pyproject.toml` is the source of truth; the requirements files mirror it.

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
| `--concurrency N` | Default 8. Higher is faster but produces more connection-level collateral, which costs extra confirmation requests to filter back out. |
| `--no-security-sweep` | Drops the deterministic injection probes. Faster, but injection coverage goes back to depending on `--cases`. |
| `--no-sequences` | Drops stateful sequence fuzzing. Use-after-delete and non-idempotent transitions then go unreachable. |
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

## Proposing fixes (`autoqa-fix`)

A separate command that reads a JSON report, asks a model for a patch, and
**verifies it by running it**. It never touches your working tree.

```bash
export OLLAMA_API_KEY="<your key>"     # $env:OLLAMA_API_KEY on PowerShell

autoqa-fix --check-key                 # confirm the key and model are reachable

autoqa-fix --report report.json            --launch "python -m uvicorn examples.vulnerable_api.app:app --port {port}"            --health /health
```

Patches land in `patches/` named by verdict, for you to review and `git apply`.

Only findings that carry a **server-side stack trace** are eligible — without a
culprit frame there is no located code to patch, so run the campaign with
`--launch`. Findings below `--min-severity` (default `high`) are skipped too,
since those are usually validation choices a human should make.

### Why the verification matters

A model will produce confident, plausible, wrong code, and reading the diff is
not a reliable filter. So each candidate is copied into a scratch tree, the
patched target is started, the exact reproducer is replayed, and the test suite
is run. Four distinct verdicts come out, and keeping them distinct is the point:

| Verdict | Meaning |
| --- | --- |
| `fixed` | Reproducer no longer fails **and** the suite still passes. |
| `still_broken` | Patch did not fix it. A hang or reset counts here, not as "unknown". |
| `broke_tests` | Bug is gone but the suite regressed — a fix that costs more than it saves. |
| `unverifiable` | The check could not run at all (e.g. the patched app will not import). |

Rejected patches are still written out: a wrong fix often points at the right
area. Nothing is applied automatically, and `fixed` means "tested", not
"reviewed" — a verified patch proves the bug is gone, not that the change is the
one you want.

Verified on the demo API with a real model: **3 of 3 eligible findings produced
accepted patches** — the SQL injection became a parameterized query with a None
check returning 404, and the `KeyError` became a 400 naming the missing fields.

Three guards worth knowing about, because all three were bugs found by running
this against a live model:

- **The patch window is the enclosing function**, found via AST, not a fixed line
  count. A line window can span a whole short file, and a reply containing only
  the function then silently deletes the imports above it.
- **A patch that removes top-level definitions is rejected** before it is ever
  run, for the same reason — that failure otherwise surfaces as a baffling
  `NameError` at import time rather than an obviously bad patch.
- **The prompt lists the names the file actually imports.** The model cannot see
  the imports from an excerpt, so left to guess it reached for `HTTPException`
  in a file that never imports it: a patch that parses, reads well, and raises
  `NameError` on the first request. It now uses `JSONResponse` because that is
  what is really there.
- **A base-indentation mismatch is corrected, not rejected.** Replies routinely
  come back indented as if nested; that discarded 2 of 3 otherwise-correct
  patches. The shift is a single constant, never a reflow, so a genuinely
  malformed reply still fails validation.

### Configuration

| Setting | Env var | Default |
| --- | --- | --- |
| API key | `OLLAMA_API_KEY` or `OLLAMA_KEY` | *required* |
| Model | `OLLAMA_MODEL` / `--model` | `gpt-oss:120b` |
| Endpoint | `OLLAMA_BASE_URL` / `--llm-base-url` | `https://ollama.com` |

Settings come from the environment or a `.env` file in the project root (see
`.env.example`); a real environment variable always wins over the file. The key
is never accepted as a CLI flag, so it stays out of shell history, and it is
never written into a report or an error message.

**The catalogue is not an entitlement list.** `/api/tags` advertises models a
given key cannot call — on a free Ollama Cloud key most answer
`403 requires a subscription`. Run `autoqa-fix --list-models` to see what yours
can actually reach; it probes each one rather than trusting the listing.

The default was chosen by benchmarking the reachable models against the demo
API's real bugs, not by name. On a free key that is `gpt-oss:120b`, which scored
4/5 on the criteria (add a guard, parameterize the SQL, return a 4xx) at ~4s per
call.

This is the one part of AutoQA that needs a model. Everything else — mutation,
oracles, clustering, minimization, sequences — is deterministic and needs no key.

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

**Security coverage is a guarantee, not a probability.** Random mutation is fine
for crash-hunting — almost any garbage triggers an unhandled `KeyError`, so the
exact value rarely matters. Injection is the opposite: only `{{7*7}}` proves
template injection, and sampling it at random made detection a lottery (~37%
after 20 cases). So alongside the random cases, every security payload is sent
to every string-ish parameter exactly once. Cost is `targets * payloads`,
independent of `--cases`, and the result is identical on every seed. Disable
with `--no-security-sweep`.

Detection requires the payload to have been *acted on*, never merely reflected:
an API that echoes `{{7*7}}` back is fine, one that answers `49` is not. Numeric
proofs are word-boundary anchored and require the payload to be absent from the
response — without that, the `49` inside `324286.6249` reads as an evaluation.

**Stateful sequences.** Independent requests cannot reach use-after-delete,
double-delete, or non-idempotent state machines: every endpoint handles a fresh
request correctly and only misbehaves on state a previous request created.
AutoQA groups operations into resources by path (`/notes`, `/notes/{id}`,
`/notes/{id}/publish` are one resource), then runs abuse patterns against them —
create-then-delete-twice, create-delete-read, repeat-an-action. Ids cannot be
known in advance, so each chain is resolved as it runs: the create step's
response is parsed and its id substituted into later steps.

Measured on `examples/crud_api/`: sequences at `--cases 5` find both planted
stateful crashes; single-request fuzzing at `--cases 50` finds neither. That
gap is a reachability difference, not a sampling-budget one, and
`tests/test_e2e_sequences.py` asserts it. Disable with `--no-sequences`.

**Clustering is the point.** A fuzzer hits the same bug hundreds of times. Runs
here typically collapse ~58 raw observations into ~14 real issues, keyed on the
server-side stack trace where one is available and a normalized error
fingerprint otherwise. Two rules keep the output honest: the offending *value*
is normalized out (so `'a.txt'` and `'../../etc/passwd'` are one bug), and the
operation is always part of the key (so one shared helper failing on two
endpoints never merges into a report whose title and reproducer disagree).

**Transport failures are confirmed before they're reported.** A dropped
connection isn't attributable to one request: HTTP keep-alive means several
requests share a connection, so one payload that makes the server hang up takes
its innocent siblings down with it — and each sibling then looks like its own
crash. Every suspected transport failure is therefore replayed alone on a fresh
connection, and dropped unless it recurs. On the demo API that discards ~10 of
11, and it also unmasks real 500s that were hiding behind the collateral.

**Minimization.** Each cluster's exemplar is delta-debugged against the live
target until it's the smallest request that still fails the same way. Transport
failures are deliberately skipped — with no status and no body, "same failure"
can't be verified, and a shrunk repro that doesn't reproduce is worse than none.

### Cost

Confirmation and minimization both replay against the live target, so a campaign
sends more requests than `operations × (cases + 1)`. At `--cases 30` on the demo
API that is ~217 fuzz requests plus ~90 replays, about 25–35s end to end.

Two flags dominate the wall clock. `--timeout` is paid in full every time a
genuine hang is re-confirmed, and `--concurrency` trades speed for connection
collateral that the confirmation pass then has to replay away. For CI, lower
both (`--timeout 5 --concurrency 4`) rather than raising the job limit. Pass
`--no-minimize` to skip the longest phase when you only need the finding list.

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
pytest                     # full suite, ~10s
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

**Injection coverage is bounded by the payload list, not by luck.** The
deterministic sweep guarantees every payload in `autoqa/fuzz/sweep.py` reaches
every string-ish parameter — but a vulnerability needing a payload that is not
on that list still goes unfound, and the sweep only probes parameters the spec
declares. A free-form object body is probed with common key names, which is a
guess.

**Traces need the target's stderr.** Without `--launch`, findings carry status
codes and response bodies but no culprit line. Handlers that catch their own
exceptions log nothing, so those get no trace either — correctly, since there's
nothing to attribute.

**Attribution is conservative.** Under concurrency, overlapping requests make
some traces ambiguous; those are left unattributed rather than guessed at. You
will see findings without a root cause even when the target did log one.

**Sequence patterns are hand-written and single-resource.** The abuse patterns
in `autoqa/fuzz/sequences.py` are a fixed list, and every chain operates on one
resource. Cross-resource authorization bugs (IDOR between two users) and
pagination invariants are not probed. A resource is only discovered when the
spec declares a `POST /things` collection alongside a `/things/{id}` item
operation; APIs that name their paths differently are skipped.

## Not built yet

From the original brief, what's deliberately still open, roughly in the order
worth doing:

1. **Richer sequence patterns.** The abuse patterns are a hand-written list and
   every chain stays within one resource. Cross-resource chains (create a note
   as user A, read it as user B) would reach IDOR, which single-resource
   sequences structurally cannot. Pagination invariants are also unprobed.
2. **Coverage-guided mutation.** Feedback from `coverage.py` would let mutation
   steer toward unexplored branches instead of re-hitting the same handler.
   Powerful, but only when the target is Python and runnable under coverage.
3. **Opening pull requests.** `autoqa-fix` proposes and verifies patches but
   never applies them. Branching, committing, and opening a PR is the remaining
   step, and it should stay behind an explicit flag: a verified patch is
   evidence that the bug is gone and the suite is green, not evidence that the
   change is the *right* one.

## Development

```bash
pip install -e ".[dev,demo]"
pytest -q                              # full suite, ~10s
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
