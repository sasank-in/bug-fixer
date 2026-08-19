"""The fix layer: patch extraction, safety guards, and verification verdicts.

The load-bearing tests here are the guards. A model can produce confident wrong
code, so the value of this feature rests entirely on refusing to trust it: never
editing the working tree, never touching dependency code, and never calling a
patch good on anything but a real test run.
"""

import json
from pathlib import Path

import pytest

from autoqa.fix.llm import LLMConfig, LLMError, OllamaClient, find_api_key, key_hint
from autoqa.fix.patcher import (
    Candidate,
    PatchError,
    build_prompt,
    extract_code,
    locate_culprit,
    propose,
    strip_gutter,
    validate_syntax,
)
from autoqa.fix.verify import Verdict, _same_failure, load_report


@pytest.fixture(autouse=True)
def isolate_dotenv(tmp_path, monkeypatch):
    """Keep the repo's real .env out of every test in this module.

    find_api_key() searches upward from the CWD for a .env, so without this a
    developer with a real key on disk sees different results than CI -- and the
    "no key configured" tests silently pass for the wrong reason.
    """
    monkeypatch.chdir(tmp_path)

# -- reply parsing ---------------------------------------------------------


def test_extracts_fenced_python():
    assert extract_code("Sure!\n```python\nx = 1\n```\nDone.") == "x = 1\n"


def test_extracts_bare_fence():
    assert extract_code("```\ny = 2\n```") == "y = 2\n"


def test_picks_the_longest_block_when_several_are_present():
    reply = "```python\nshort\n```\ntext\n```python\nthe = 1\nlonger = 2\nblock = 3\n```"
    assert "longer" in extract_code(reply)


def test_accepts_unfenced_reply_that_parses():
    assert extract_code("def f():\n    return 1\n").startswith("def f()")


def test_rejects_unfenced_prose():
    """Prose must never be spliced into source as if it were code."""
    with pytest.raises(PatchError, match="neither a fenced"):
        extract_code("I think the bug is on line 42, you should add a check.")


def test_rejects_empty_reply():
    with pytest.raises(PatchError):
        extract_code("   ")


def test_honours_cannot_fix():
    with pytest.raises(PatchError, match="declined"):
        extract_code("CANNOT_FIX")


def test_strips_echoed_line_number_gutter():
    """Models echo the gutter back; left in place it is a syntax error."""
    code = "   10| def f():\n   11|     return 1\n   12| # end\n"
    assert strip_gutter(code) == "def f():\n    return 1\n# end"


def test_does_not_strip_incidental_pipes():
    code = "flags = a | b\nother = c | d\n"
    assert strip_gutter(code) == code


def test_gutter_stripped_through_extract():
    reply = "```python\n    5| def f():\n    6|     return 2\n    7| pass\n```"
    assert "|" not in extract_code(reply)


# -- candidate mechanics ---------------------------------------------------


def make_file(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "app.py"
    path.write_text(body, encoding="utf-8")
    return path


def test_apply_to_splices_at_the_right_lines():
    candidate = Candidate("s", Path("x"), 2, 3, "b\nc\n", "B\nC\n")
    assert candidate.apply_to("a\nb\nc\nd\n") == "a\nB\nC\nd\n"


def test_apply_to_preserves_a_missing_trailing_newline():
    candidate = Candidate("s", Path("x"), 1, 1, "a\n", "A")
    assert candidate.apply_to("a\nb\n") == "A\nb\n"


def test_noop_is_detected():
    assert Candidate("s", Path("x"), 1, 1, "a\n", "a\n").is_noop


def test_validate_syntax_accepts_a_good_patch(tmp_path):
    path = make_file(tmp_path, "def f():\n    return 1\n")
    candidate = Candidate("s", path, 2, 2, "    return 1\n", "    return 2\n")
    validate_syntax(candidate)  # must not raise


def test_validate_syntax_rejects_broken_indentation(tmp_path):
    """A snippet can parse alone and still break the file it lands in."""
    path = make_file(tmp_path, "def f():\n    return 1\n")
    candidate = Candidate("s", path, 2, 2, "    return 1\n", "return 2\n")
    with pytest.raises(PatchError, match="does not parse in place"):
        validate_syntax(candidate)


def test_validate_syntax_rejects_a_syntax_error(tmp_path):
    path = make_file(tmp_path, "def f():\n    return 1\n")
    candidate = Candidate("s", path, 2, 2, "    return 1\n", "    return (\n")
    with pytest.raises(PatchError):
        validate_syntax(candidate)


# -- safety guards: the reason this feature is trustworthy ----------------


def finding_with(culprit: str, **kw) -> dict:
    base = {
        "signature": "sig",
        "title": "t",
        "detail": "d",
        "severity": "high",
        "stack_trace": {"culprit": culprit, "exception_type": "E", "message": "m"},
        "reproducer": {"curl": "curl x", "method": "GET", "path": "/x",
                       "query": {}, "headers": {}, "body": None},
        "observed": {"status": 500},
    }
    base.update(kw)
    return base


def test_refuses_to_patch_outside_the_repo(tmp_path):
    """A trace can point into site-packages; rewriting a dependency would be
    both wrong and invisible to review."""
    outside = tmp_path / "elsewhere" / "lib.py"
    outside.parent.mkdir()
    outside.write_text("x = 1\n", encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()

    with pytest.raises(PatchError, match="outside the repository"):
        locate_culprit(finding_with(f"{outside}:1 in f"), repo)


def test_refuses_non_python_files(tmp_path):
    target = tmp_path / "config.yaml"
    target.write_text("a: 1\n", encoding="utf-8")
    with pytest.raises(PatchError, match="only Python"):
        locate_culprit(finding_with(f"{target}:1 in f"), tmp_path)


def test_requires_a_culprit_frame():
    with pytest.raises(PatchError, match="no culprit frame"):
        locate_culprit({"stack_trace": {}}, Path("."))


def test_requires_a_stack_trace_at_all():
    with pytest.raises(PatchError, match="no culprit frame"):
        locate_culprit({}, Path("."))


def test_rejects_an_unparseable_culprit():
    with pytest.raises(PatchError, match="could not parse"):
        locate_culprit(finding_with("no line number here"), Path("."))


def test_missing_file_is_reported_clearly(tmp_path):
    with pytest.raises(PatchError, match="not found"):
        locate_culprit(finding_with(f"{tmp_path / 'gone.py'}:1 in f"), tmp_path)


def test_locates_a_valid_culprit(tmp_path):
    path = make_file(tmp_path, "def f():\n    return 1\n")
    found, line, _ = locate_culprit(finding_with(f"{path}:2 in f"), tmp_path)
    assert found == path and line == 2


class FakeClient:
    def __init__(self, reply: str):
        self.reply = reply
        self.calls = 0

    def complete(self, system, user):
        self.calls += 1
        self.last_prompt = user
        return self.reply


def test_propose_rejects_an_unchanged_reply(tmp_path):
    path = make_file(tmp_path, "def f():\n    return 1\n")
    client = FakeClient("```python\ndef f():\n    return 1\n```")
    with pytest.raises(PatchError, match="unchanged"):
        propose(finding_with(f"{path}:2 in f"), client, tmp_path)


def test_propose_returns_a_validated_candidate(tmp_path):
    path = make_file(tmp_path, "def f():\n    return 1\n")
    client = FakeClient("```python\ndef f():\n    return 2\n```")
    candidate = propose(finding_with(f"{path}:2 in f"), client, tmp_path)
    assert "return 2" in candidate.replacement
    assert client.calls == 1


def test_propose_does_not_write_to_the_source_file(tmp_path):
    """The whole promise of this layer: the working tree is never touched."""
    path = make_file(tmp_path, "def f():\n    return 1\n")
    before = path.read_text(encoding="utf-8")
    client = FakeClient("```python\ndef f():\n    return 2\n```")
    propose(finding_with(f"{path}:2 in f"), client, tmp_path)
    assert path.read_text(encoding="utf-8") == before


# -- prompt ----------------------------------------------------------------


def test_prompt_carries_the_evidence_the_model_needs():
    prompt = build_prompt(
        title="HTTP 500 on GET /x", detail="crashed",
        reproducer="curl -i /x?q=1", observed="HTTP 500",
        exception="KeyError: 'a'", culprit="app.py:7 in handler",
        code="def handler():\n    pass\n", start_line=5,
    )
    for expected in ("HTTP 500 on GET /x", "curl -i /x?q=1", "KeyError", "app.py:7"):
        assert expected in prompt
    # Line numbers help the model locate the fault but must not be echoed back.
    assert "    5|" in prompt
    assert "do NOT include them" in prompt


# -- verification verdicts -------------------------------------------------


@pytest.mark.parametrize(
    "after,claimed,still_broken",
    [
        (500, 500, True),    # unchanged
        (400, 500, False),   # rejected properly — the correct fix
        (422, 500, False),
        (200, 500, False),
        (503, 500, True),    # still a 5xx, just a different one
        (None, 500, True),   # no response at all
        (200, None, False),  # original was a transport failure
    ],
)
def test_same_failure_classification(after, claimed, still_broken):
    assert _same_failure(after, claimed) is still_broken


def test_load_report_reads_clusters(tmp_path):
    path = tmp_path / "r.json"
    path.write_text(json.dumps({"clusters": [{"signature": "a"}]}), encoding="utf-8")
    assert load_report(path) == [{"signature": "a"}]


def test_load_report_rejects_a_non_report(tmp_path):
    path = tmp_path / "r.json"
    path.write_text(json.dumps({"something": "else"}), encoding="utf-8")
    with pytest.raises(ValueError, match="does not look like"):
        load_report(path)


def test_verdicts_are_distinct():
    # Four outcomes must stay distinguishable; collapsing any pair would hide
    # the difference between "wrong fix" and "could not check".
    assert len({v.value for v in Verdict}) == 4


# -- key handling ----------------------------------------------------------


def test_key_is_read_from_the_environment(monkeypatch):
    monkeypatch.setenv("OLLAMA_API_KEY", "secret-value")
    assert find_api_key() == "secret-value"


def test_alternate_key_var_is_accepted(monkeypatch):
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
    monkeypatch.setenv("OLLAMA_KEY", "k2")
    assert find_api_key() == "k2"


def test_blank_key_counts_as_absent(monkeypatch):
    monkeypatch.setenv("OLLAMA_API_KEY", "   ")
    monkeypatch.delenv("OLLAMA_KEY", raising=False)
    # A whitespace-only value is a configuration mistake, not a key.
    assert find_api_key() is None


def test_client_refuses_to_construct_without_a_key(monkeypatch):
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
    monkeypatch.delenv("OLLAMA_KEY", raising=False)
    with pytest.raises(LLMError, match="no Ollama API key"):
        OllamaClient(LLMConfig())


def test_key_hint_never_contains_a_key(monkeypatch):
    monkeypatch.setenv("OLLAMA_API_KEY", "super-secret-abc123")
    assert "super-secret-abc123" not in key_hint()


def test_default_endpoint_is_ollama_cloud():
    assert LLMConfig().base_url == "https://ollama.com"


# -- .env loading ----------------------------------------------------------
# Added after discovering the tool could not see a key the user had put in a
# root-level .env: nothing loaded the file, so the key was invisible.


def clear_env(monkeypatch):
    for name in ("OLLAMA_API_KEY", "OLLAMA_KEY", "OLLAMA_MODEL", "OLLAMA_BASE_URL"):
        monkeypatch.delenv(name, raising=False)


def test_key_is_read_from_a_dotenv_file(tmp_path, monkeypatch):
    from autoqa.fix.llm import load_dotenv

    clear_env(monkeypatch)
    (tmp_path / ".env").write_text("OLLAMA_API_KEY=from-dotenv\n", encoding="utf-8")
    load_dotenv(tmp_path)
    assert find_api_key() == "from-dotenv"


def test_alternate_name_in_dotenv_is_accepted(tmp_path, monkeypatch):
    """The user's file used OLLAMA_KEY, not OLLAMA_API_KEY."""
    from autoqa.fix.llm import load_dotenv

    clear_env(monkeypatch)
    (tmp_path / ".env").write_text("OLLAMA_KEY=alt-name\n", encoding="utf-8")
    load_dotenv(tmp_path)
    assert find_api_key() == "alt-name"


def test_real_environment_wins_over_dotenv(tmp_path, monkeypatch):
    """.env is a local convenience, not an override of a deliberate setting."""
    from autoqa.fix.llm import load_dotenv

    clear_env(monkeypatch)
    monkeypatch.setenv("OLLAMA_API_KEY", "from-shell")
    (tmp_path / ".env").write_text("OLLAMA_API_KEY=from-file\n", encoding="utf-8")
    load_dotenv(tmp_path)
    assert find_api_key() == "from-shell"


def test_dotenv_is_found_in_a_parent_directory(tmp_path, monkeypatch):
    from autoqa.fix.llm import load_dotenv

    clear_env(monkeypatch)
    (tmp_path / ".env").write_text("OLLAMA_API_KEY=parent\n", encoding="utf-8")
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    load_dotenv(nested)
    assert find_api_key() == "parent"


@pytest.mark.parametrize(
    "line,expected",
    [
        ('OLLAMA_API_KEY="quoted"', "quoted"),
        ("OLLAMA_API_KEY='single'", "single"),
        ("  OLLAMA_API_KEY = spaced  ", "spaced"),
        ("export OLLAMA_API_KEY=exported", "exported"),
    ],
)
def test_dotenv_tolerates_common_formatting(tmp_path, monkeypatch, line, expected):
    from autoqa.fix.llm import load_dotenv

    clear_env(monkeypatch)
    (tmp_path / ".env").write_text(line + "\n", encoding="utf-8")
    load_dotenv(tmp_path)
    assert find_api_key() == expected


def test_dotenv_ignores_comments_and_blanks(tmp_path, monkeypatch):
    from autoqa.fix.llm import load_dotenv

    clear_env(monkeypatch)
    (tmp_path / ".env").write_text(
        "# a comment\n\nOLLAMA_API_KEY=k\n# OLLAMA_MODEL=commented-out\n",
        encoding="utf-8",
    )
    load_dotenv(tmp_path)
    assert find_api_key() == "k"
    assert "OLLAMA_MODEL" not in __import__("os").environ


def test_dotenv_only_reads_known_names(tmp_path, monkeypatch):
    """A stray assignment must not silently change unrelated behaviour."""
    import os

    from autoqa.fix.llm import load_dotenv

    clear_env(monkeypatch)
    monkeypatch.delenv("SOME_OTHER_SECRET", raising=False)
    (tmp_path / ".env").write_text(
        "OLLAMA_API_KEY=k\nSOME_OTHER_SECRET=should-not-load\n", encoding="utf-8"
    )
    load_dotenv(tmp_path)
    assert "SOME_OTHER_SECRET" not in os.environ


def test_missing_dotenv_is_not_an_error(tmp_path, monkeypatch):
    from autoqa.fix.llm import load_dotenv

    clear_env(monkeypatch)
    load_dotenv(tmp_path)  # must not raise
    assert find_api_key() is None


def test_dotenv_can_set_model_and_endpoint(tmp_path, monkeypatch):
    from autoqa.fix.llm import load_dotenv

    clear_env(monkeypatch)
    (tmp_path / ".env").write_text(
        "OLLAMA_API_KEY=k\nOLLAMA_MODEL=some-model\nOLLAMA_BASE_URL=https://gw.example\n",
        encoding="utf-8",
    )
    load_dotenv(tmp_path)
    config = LLMConfig.from_env()
    assert config.model == "some-model"
    assert config.base_url == "https://gw.example"
