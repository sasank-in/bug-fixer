# Contributing

```bash
pip install -e ".[dev,demo]"
pytest -q                     # 150 tests, ~4s
ruff check autoqa/ tests/     # lint
```

## The rule everything else follows from

**A finding must be true, or it must not be reported.**

A fuzzer that cries wolf gets muted, and then it may as well not exist. Every
design decision below is downstream of that. When a change forces a choice
between "report something possibly wrong" and "report nothing", choose nothing —
and say so in the output where a reader might expect a result.

Concretely, this is why:

- An ambiguous stack trace goes unattributed rather than attached to a guess.
  Under concurrency several requests overlap one trace window; committing to the
  nearest one would point a reader at unrelated code.
- `culprit` returns `None` when a trace contains no application frames, instead
  of falling back to the deepest library frame.
- Transport failures are never minimized. With no status and no body, "is this
  still the same bug?" cannot be answered, and a shrunk reproducer that does not
  reproduce is worse than the original request.
- The operation is always part of a cluster signature, even when a stack trace
  identifies the root cause, so a shared helper failing on two endpoints never
  produces one report whose title and reproducer disagree.

## Invariants the tests enforce

These are the ones worth knowing before changing anything:

| Invariant | Where |
| --- | --- |
| The curl reproducer encodes exactly like the executor sent | `tests/test_render.py` |
| No cluster spans more than one operation | `tests/test_e2e.py` |
| A cluster's title, detail, and reproducer all describe its exemplar | `tests/test_analysis.py` |
| A culprit frame never points into a dependency | `tests/test_e2e.py` |
| Our own encoding errors never surface as transport failures | `tests/test_executor.py` |
| Report JSON is strictly parseable, whatever the payload | `tests/test_render.py` |

The e2e suite is the one that matters most: it runs a real campaign against
`examples/vulnerable_api/` and asserts on the findings. If you change anything in
`analysis/`, run it before assuming you are done.

## Reproducer fidelity

`runner/http.py` exists solely so the executor and the reporter cannot drift.
Both encode bodies through `encode_body` and resolve content-type through
`with_default_content_type`. If you add a way to build a request, route it
through there too.

Two encoding traps that have already caused bugs:

- **Query values are not strings.** `urlencode({"t": [1,2]})` gives
  `t=%5B1%2C+2%5D`; httpx sends `t=1&t=2`. Build URLs with `request_url`, which
  goes through httpx, not by hand.
- **Header names are case-insensitive.** A plain dict merge lets a spec-declared
  `content-type` coexist with our `Content-Type`; httpx then joins them with a
  comma and sends a malformed header we would blame on the target. Use
  `has_header`.

## Adding an oracle

An oracle is `Callable[[Result], list[Finding]]`. Add it to `DEFAULT_ORACLES` in
`analysis/oracles.py` and test both directions — that it fires on the bug, and
that it stays silent on correct behaviour. The second test is the important one.
A 400 on garbage input is the target working as intended and must never be
reported.

## Adding a mutator

Add the function to `fuzz/mutators.py`, wire it into `pick_mutator` for the types
it suits, and give it a tag that reads well in a report (`boundary_int`, not
`m3`). Every value a mutator can emit must survive `encode_body` — there is a
test that walks all the pools and asserts exactly that.

## Adding stack trace support for a language

Write a `_parse_<lang>` in `analysis/traces.py`, register its detection in
`_try_parse`, and add the language's real-world log format to
`tests/test_traces.py`. Use output copied from an actual runtime, not
hand-written samples: the Python parser broke on 3.11+ caret markers precisely
because the original tests used idealized tracebacks.

Also extend `_LIBRARY_MARKERS` so `culprit` can tell application code from
dependency code in that ecosystem.
