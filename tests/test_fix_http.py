"""The Ollama Cloud request shape.

Hand-rolled over httpx rather than an SDK, so the wire format is this project's
responsibility and needs pinning: right URL, right auth header, non-streaming,
and a key that never leaks into an error message.
"""

import json

import httpx
import pytest

from autoqa.fix.llm import LLMConfig, LLMError, OllamaClient


def client_with(handler, monkeypatch, key="k"):
    """An OllamaClient whose httpx.post is routed to `handler`."""
    monkeypatch.setenv("OLLAMA_API_KEY", key)
    client = OllamaClient(LLMConfig(model="m", base_url="https://ollama.com"))
    transport = httpx.MockTransport(handler)

    def fake_post(url, **kwargs):
        with httpx.Client(transport=transport) as inner:
            return inner.post(url, **kwargs)

    monkeypatch.setattr(httpx, "post", fake_post)
    return client


def test_native_request_shape(monkeypatch):
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = json.loads(request.content)
        return httpx.Response(
            200, json={"message": {"content": "```python\nx=1\n```"}}
        )

    reply = client_with(handler, monkeypatch).complete("sys", "usr")

    assert "x=1" in reply
    assert seen["url"] == "https://ollama.com/api/chat"
    assert seen["auth"] == "Bearer k"
    # Streaming would need a different parser; the client asks for one blob.
    assert seen["body"]["stream"] is False
    assert [m["role"] for m in seen["body"]["messages"]] == ["system", "user"]


def test_openai_shape_is_tolerated(monkeypatch):
    """Some gateways answer /api/chat in the OpenAI shape; failing would be
    gratuitous when the content is right there."""

    def handler(request):
        return httpx.Response(200, json={"choices": [{"message": {"content": "hi"}}]})

    assert client_with(handler, monkeypatch).complete("s", "u") == "hi"


def test_401_names_the_key_as_the_problem(monkeypatch):
    def handler(request):
        return httpx.Response(401, text="unauthorized")

    with pytest.raises(LLMError, match="rejected the API key"):
        client_with(handler, monkeypatch).complete("s", "u")


def test_404_points_at_model_or_base_url(monkeypatch):
    """The two plausible causes, since the user cannot tell them apart alone."""

    def handler(request):
        return httpx.Response(404, text="no")

    with pytest.raises(LLMError, match=r"not\s+available|base URL"):
        client_with(handler, monkeypatch).complete("s", "u")


def test_empty_content_is_an_error(monkeypatch):
    def handler(request):
        return httpx.Response(200, json={"message": {"content": "   "}})

    with pytest.raises(LLMError, match="no content"):
        client_with(handler, monkeypatch).complete("s", "u")


def test_non_json_reply_is_an_error(monkeypatch):
    def handler(request):
        return httpx.Response(200, text="<html>gateway error</html>")

    with pytest.raises(LLMError, match="non-JSON"):
        client_with(handler, monkeypatch).complete("s", "u")


def test_key_never_appears_in_an_error(monkeypatch):
    """An error message can end up in a log or a paste; the key must not."""

    def handler(request):
        return httpx.Response(500, text="boom")

    with pytest.raises(LLMError) as excinfo:
        client_with(handler, monkeypatch, key="SECRET123").complete("s", "u")
    assert "SECRET123" not in str(excinfo.value)


def test_timeout_is_reported_as_unreachable(monkeypatch):
    def handler(request):
        raise httpx.ConnectTimeout("slow")

    with pytest.raises(LLMError, match="could not reach"):
        client_with(handler, monkeypatch).complete("s", "u")
