"""Indentation realignment and available-name discovery.

Both exist because of failures seen on a real run: two of three patches were
discarded for base-indentation mismatch, and the third referenced an exception
class the target file never imported, so it raised NameError on first request.
"""

import pytest

from autoqa.fix.indent import base_indent, realign
from autoqa.fix.patcher import available_names

# -- indentation -----------------------------------------------------------

TOP = '@app.get("/x")\ndef f():\n    return 1\n'


def test_over_indented_reply_is_brought_back():
    """The failure that discarded 2 of 3 patches on the first live run."""
    reply = '    @app.get("/x")\n    def f():\n        return 2\n'
    assert realign(reply, TOP) == '@app.get("/x")\ndef f():\n    return 2\n'


def test_under_indented_reply_is_pushed_in():
    nested = "    def method(self):\n        return 1\n"
    reply = "def method(self):\n    return 2\n"
    assert realign(reply, nested) == "    def method(self):\n        return 2\n"


def test_matching_indentation_is_untouched():
    assert realign(TOP, TOP) == TOP


def test_relative_structure_is_preserved():
    reply = "    def f():\n        if x:\n            return 1\n"
    out = realign(reply, TOP)
    widths = [len(line) - len(line.lstrip()) for line in out.splitlines()]
    assert widths == [0, 4, 8]


def test_blank_lines_are_not_padded():
    """Padding a blank line would add trailing whitespace."""
    nested = "    a = 1\n"
    out = realign("a = 1\n\nb = 2\n", nested)
    assert "\n\n" in out
    assert not any(line.isspace() for line in out.splitlines())


def test_trailing_newline_is_preserved():
    assert realign("    x = 1\n", "x = 1\n").endswith("\n")
    assert not realign("    x = 1", "x = 1").endswith("\n")


@pytest.mark.parametrize("text", ["", "\n", "   \n"])
def test_blank_input_is_returned_unchanged(text):
    assert realign(text, TOP) == text
    assert realign(TOP, text) == TOP


def test_base_indent_ignores_blank_lines():
    assert base_indent("\n    a\n\n        b\n") == 4


def test_base_indent_of_nothing_is_none():
    assert base_indent("\n  \n") is None


def test_internally_broken_indentation_is_not_repaired():
    """Realignment is a constant shift, never a reflow: a genuinely malformed
    reply must still fail validation rather than be silently 'fixed'."""
    broken = "def f():\nreturn 1\n"
    out = realign(broken, TOP)
    assert out == broken  # base already matches, so nothing is touched


# -- available names -------------------------------------------------------


def test_reports_imported_names():
    src = "from fastapi import Body, FastAPI\nimport json\n"
    names = available_names(src)
    assert {"Body", "FastAPI", "json"} <= set(names)


def test_reports_aliases_not_original_names():
    names = available_names("import numpy as np\nfrom x import y as z\n")
    assert "np" in names and "numpy" not in names
    assert "z" in names and "y" not in names


def test_reports_module_level_definitions():
    src = "def handler():\n    pass\n\n\nclass Model:\n    pass\n\n\nDB = {}\n"
    names = available_names(src)
    assert {"handler", "Model", "DB"} <= set(names)


def test_omits_names_that_are_not_imported():
    """The bug this prevents: the model reached for HTTPException, which the
    demo app never imports, producing a NameError at request time."""
    src = "from fastapi import Body, FastAPI, Query\n"
    assert "HTTPException" not in available_names(src)


def test_unparseable_source_yields_no_names():
    assert available_names("def broken(:\n") == []


def test_prompt_lists_the_available_names():
    from autoqa.fix.patcher import build_prompt

    prompt = build_prompt(
        title="t", detail="d", reproducer="r", observed="HTTP 500",
        exception="E", culprit="a.py:1 in f", code="pass\n", start_line=1,
        available=["JSONResponse", "Query"],
    )
    assert "JSONResponse" in prompt
    assert "nothing else exists at runtime" in prompt


def test_prompt_is_explicit_when_names_are_unknown():
    from autoqa.fix.patcher import build_prompt

    prompt = build_prompt(
        title="t", detail="d", reproducer="r", observed="HTTP 500",
        exception="E", culprit="a.py:1 in f", code="pass\n", start_line=1,
        available=None,
    )
    assert "builtins" in prompt
