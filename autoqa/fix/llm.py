"""Minimal Ollama Cloud client.

Deliberately hand-rolled over httpx, which is already a dependency, rather than
pulling in an SDK: the surface used here is one POST to /api/chat, and an extra
dependency for that would be a poor trade.

The API key is read from the environment only. It is never accepted as a CLI
argument (shell history), never logged, and never written into a report.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

import httpx

DEFAULT_BASE_URL = "https://ollama.com"
DEFAULT_MODEL = "qwen2.5-coder:7b"

# Env vars checked in order. OLLAMA_API_KEY is Ollama's own convention.
_KEY_VARS = ("OLLAMA_API_KEY", "OLLAMA_KEY")


class LLMError(RuntimeError):
    """Raised when the model cannot be reached or returns an unusable reply."""


@dataclass(frozen=True)
class LLMConfig:
    model: str = DEFAULT_MODEL
    base_url: str = DEFAULT_BASE_URL
    timeout: float = 120.0
    # Low but non-zero: patch generation wants determinism, and some servers
    # behave oddly at exactly 0.
    temperature: float = 0.1

    @classmethod
    def from_env(cls, model: str | None = None, base_url: str | None = None) -> LLMConfig:
        return cls(
            model=model or os.environ.get("OLLAMA_MODEL") or DEFAULT_MODEL,
            base_url=(base_url or os.environ.get("OLLAMA_BASE_URL") or DEFAULT_BASE_URL).rstrip("/"),
        )


def find_api_key() -> str | None:
    for name in _KEY_VARS:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return None


def key_hint() -> str:
    """Actionable message for the missing-key case, naming no secret."""
    return (
        "no Ollama API key found. Set OLLAMA_API_KEY in the environment "
        "(not as a CLI flag, so it stays out of shell history):\n"
        '  PowerShell:  $env:OLLAMA_API_KEY = "<your key>"\n'
        '  bash:        export OLLAMA_API_KEY="<your key>"'
    )


class OllamaClient:
    """Single-purpose chat client for Ollama Cloud's native /api/chat."""

    def __init__(self, config: LLMConfig | None = None, api_key: str | None = None) -> None:
        self.config = config or LLMConfig.from_env()
        self._api_key = api_key or find_api_key()
        if not self._api_key:
            raise LLMError(key_hint())

    def complete(self, system: str, user: str) -> str:
        """One non-streaming chat turn. Returns the assistant's text."""
        payload = {
            "model": self.config.model,
            "stream": False,
            "options": {"temperature": self.config.temperature},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        url = f"{self.config.base_url}/api/chat"

        try:
            response = httpx.post(
                url,
                json=payload,
                timeout=self.config.timeout,
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
            )
        except httpx.HTTPError as exc:
            raise LLMError(f"could not reach {url}: {exc}") from exc

        if response.status_code == 401:
            raise LLMError(
                f"{url} rejected the API key (401). Check OLLAMA_API_KEY, and that "
                f"it belongs to this endpoint."
            )
        if response.status_code == 404:
            raise LLMError(
                f"{url} returned 404. Either the model {self.config.model!r} is not "
                f"available on this account, or the base URL is wrong "
                f"(--llm-base-url / OLLAMA_BASE_URL)."
            )
        if response.status_code >= 400:
            raise LLMError(
                f"{url} returned {response.status_code}: {response.text[:300]}"
            )

        try:
            body = response.json()
        except ValueError as exc:
            raise LLMError(f"non-JSON reply from {url}: {response.text[:200]}") from exc

        # Native shape: {"message": {"content": "..."}}. Tolerate the
        # OpenAI-compatible shape too, since some gateways answer that way even
        # on /api/chat and failing on it would be gratuitous.
        content = (body.get("message") or {}).get("content")
        if content is None:
            choices = body.get("choices") or []
            if choices:
                content = (choices[0].get("message") or {}).get("content")
        if not content or not str(content).strip():
            raise LLMError(
                f"reply contained no content: {json.dumps(body)[:300]}"
            )
        return str(content)
