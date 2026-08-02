from autoqa.analysis.traces import extract_traces
from autoqa.runner.process import LogLine

PYTHON_LOG = """\
INFO: request started
Traceback (most recent call last):
  File "/app/main.py", line 42, in handler
    return process(payload)
  File "/app/service.py", line 17, in process
    return data["missing"]
KeyError: 'missing'
INFO: request finished
"""

NODE_LOG = """\
TypeError: Cannot read properties of undefined (reading 'id')
    at getUser (/app/routes/user.js:31:22)
    at /app/node_modules/express/lib/router.js:281:10
"""

JAVA_LOG = """\
java.lang.NullPointerException: user is null
\tat com.example.UserService.find(UserService.java:88)
\tat com.example.UserController.get(UserController.java:24)
"""

GO_LOG = """\
panic: runtime error: index out of range [5] with length 3

goroutine 1 [running]:
main.handler(0x0)
\t/app/main.go:27 +0x1d
"""


def as_lines(text: str, start: float = 100.0) -> list[LogLine]:
    return [
        LogLine(start + i, "stderr", line)
        for i, line in enumerate(text.splitlines())
    ]


def test_parses_python_traceback():
    traces = extract_traces(as_lines(PYTHON_LOG))
    assert len(traces) == 1
    trace = traces[0]
    assert trace.exception_type == "KeyError"
    assert trace.message == "'missing'"
    assert len(trace.frames) == 2
    assert trace.frames[-1].function == "process"
    assert trace.frames[-1].line == 17


def test_python_culprit_skips_library_frames():
    log = """\
Traceback (most recent call last):
  File "/app/main.py", line 10, in handler
    raise ValueError("x")
  File "/usr/lib/python3/site-packages/lib.py", line 99, in inner
    boom()
ValueError: x
"""
    trace = extract_traces(as_lines(log))[0]
    assert trace.culprit is not None
    assert "main.py" in trace.culprit.file


def test_parses_node_stack():
    trace = extract_traces(as_lines(NODE_LOG))[0]
    assert trace.language == "javascript"
    assert trace.exception_type == "TypeError"
    assert trace.frames[0].function == "getUser"


def test_node_culprit_skips_node_modules():
    trace = extract_traces(as_lines(NODE_LOG))[0]
    assert trace.culprit is not None
    assert "node_modules" not in trace.culprit.file


def test_culprit_is_none_when_trace_is_all_library_code():
    log = """\
Traceback (most recent call last):
  File "/venv/lib/python3.11/site-packages/uvicorn/protocols/http.py", line 4, in run
    parse()
  File "/venv/lib/python3.11/site-packages/httptools/parser.py", line 9, in parse
    raise ValueError("bad header")
ValueError: bad header
"""
    trace = extract_traces(as_lines(log))[0]
    # No application frame exists, so claiming one would be a false lead.
    assert trace.culprit is None
    assert trace.in_dependency is True
    assert trace.deepest_frame is not None


def test_windows_site_packages_path_is_recognised_as_library():
    log = """\
Traceback (most recent call last):
  File "C:\\\\Users\\\\me\\\\miniconda3\\\\Lib\\\\site-packages\\\\uvicorn\\\\x.py", line 4, in run
    boom()
ValueError: bad
"""
    trace = extract_traces(as_lines(log))[0]
    assert trace.in_dependency is True


def test_parses_java_stack():
    trace = extract_traces(as_lines(JAVA_LOG))[0]
    assert trace.language == "java"
    assert trace.exception_type == "java.lang.NullPointerException"
    assert len(trace.frames) == 2


def test_parses_go_panic():
    trace = extract_traces(as_lines(GO_LOG))[0]
    assert trace.language == "go"
    assert "index out of range" in trace.message


def test_signature_is_stable_across_line_shifts():
    a = extract_traces(as_lines(PYTHON_LOG))[0]
    shifted = PYTHON_LOG.replace("line 42", "line 55").replace("line 17", "line 20")
    b = extract_traces(as_lines(shifted))[0]
    # Same bug, file edited above it — must still cluster together.
    assert a.signature == b.signature


def test_signature_differs_for_different_bugs():
    a = extract_traces(as_lines(PYTHON_LOG))[0]
    b = extract_traces(as_lines(NODE_LOG))[0]
    assert a.signature != b.signature


def test_traces_carry_timestamps():
    trace = extract_traces(as_lines(PYTHON_LOG, start=500.0))[0]
    assert trace.timestamp > 0


def test_plain_logs_yield_nothing():
    assert extract_traces(as_lines("INFO: all good\nINFO: still fine\n")) == []


# The following formats are taken verbatim from real uvicorn/FastAPI output on
# Python 3.13 — they broke the first version of this parser.

UVICORN_LOG = r'''
ERROR:    Exception in ASGI application
Traceback (most recent call last):
  File "C:\Users\me\miniconda3\Lib\site-packages\uvicorn\protocols\http\h11_impl.py", line 403, in run_asgi
    result = await app(self.scope, self.receive, self.send)
  File "C:\Users\me\miniconda3\Lib\site-packages\fastapi\routing.py", line 670, in app
    raw_response = await run_endpoint_function(
                   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    ...<3 lines>...
    )
    ^
  File "C:\Users\me\bug-fixer\examples\vulnerable_api\app.py", line 46, in get_user
    cursor = _db.execute(f"SELECT id, name, role FROM users WHERE id = {user_id}")
sqlite3.OperationalError: no such column: abc
'''


def test_parses_python_313_caret_markers():
    """Python 3.11+ emits ^^^^ underlines that must not terminate the frame scan."""
    traces = extract_traces(as_lines(UVICORN_LOG))
    assert len(traces) == 1
    trace = traces[0]
    assert trace.exception_type == "sqlite3.OperationalError"
    assert trace.message == "no such column: abc"


def test_parses_elision_marker():
    trace = extract_traces(as_lines(UVICORN_LOG))[0]
    # "...<3 lines>..." sits between frames; all three frames must survive it.
    assert len(trace.frames) == 3


def test_culprit_found_past_deep_framework_stack():
    trace = extract_traces(as_lines(UVICORN_LOG))[0]
    assert trace.culprit is not None
    assert "app.py" in trace.culprit.file
    assert trace.culprit.function == "get_user"
    assert trace.culprit.line == 46


def test_dotted_exception_type_parsed():
    log = "Traceback (most recent call last):\n" '  File "/a.py", line 1, in f\n' "psycopg2.errors.UniqueViolation: dup key\n"
    trace = extract_traces(as_lines(log))[0]
    assert trace.exception_type == "psycopg2.errors.UniqueViolation"


def test_chained_exception_merges_into_one_trace():
    log = """\
Traceback (most recent call last):
  File "/app/a.py", line 1, in f
    boom()
KeyError: 'k'

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/app/b.py", line 2, in g
    rethrow()
ValueError: wrapped
"""
    traces = extract_traces(as_lines(log))
    # The final exception is what surfaced; it should not be reported as two
    # unrelated bugs.
    assert len(traces) == 1
    assert traces[0].exception_type == "ValueError"


def test_no_unknown_error_for_wellformed_traces():
    for log in (UVICORN_LOG, PYTHON_LOG):
        for trace in extract_traces(as_lines(log)):
            assert trace.exception_type != "UnknownError"
            assert trace.frames
