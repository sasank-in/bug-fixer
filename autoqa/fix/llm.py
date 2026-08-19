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
from pathlib import Path

import httpx

DEFAULT_BASE_URL = "https://ollama.com"
# Ollama Cloud's catalogue is not the same as what a given key may call: most
# entries in /api/tags answer 403 "requires a subscription". Run
# `autoqa-fix --list-models` to see what a key can actually reach.
#
# This default was measured, not chosen by name -- see tools/benchmark_models.py.
# Across 3 repetitions on the demo API's real bugs, on a free-tier key:
#   gemma4:31b        86%  median  2.5s
#   gpt-oss:120b      71%  median  5.1s
#   nemotron-3-super  71%  median 12.6s
# Re-run the benchmark if the catalogue changes; a single sample is noise, since
# one model measured 3s and 38s on the same prompt in different runs.
DEFAULT_MODEL = "gemma4:31b"

# Env vars checked in order. OLLAMA_API_KEY is Ollama's own convention.
_KEY_VARS = ("OLLAMA_API_KEY", "OLLAMA_KEY")

# Names read out of a .env file, mirroring the env vars above.
_DOTENV_NAMES = (*_KEY_VARS, "OLLAMA_MODEL", "OLLAMA_BASE_URL")


def load_dotenv(start: Path | None = None) -> None:
    """Load Ollama settings from the nearest .env, without adding a dependency.

    A real environment variable always wins: .env is a convenience for local
    work, not an override of what the shell or CI deliberately set.

    Only the handful of names this module uses are read. Importing every
    assignment out of an arbitrary file would let a stray line in someone's .env
    quietly change unrelated behaviour.
    """
    directory = (start or Path.cwd()).resolve()
    for candidate in (directory, *directory.parents):
        path = candidate / ".env"
        if not path.is_file():
            continue
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError:
            return
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, _, value = line.partition("=")
            name = name.strip().removeprefix("export ").strip()
            if name not in _DOTENV_NAMES or os.environ.get(name):
                continue
            value = value.strip()
            # Strip one layer of matching quotes, which people add out of habit.
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            if value:
                os.environ[name] = value
        return  # nearest .env wins; do not merge several


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
        load_dotenv()
        return cls(
            model=model or os.environ.get("OLLAMA_MODEL") or DEFAULT_MODEL,
            base_url=(base_url or os.environ.get("OLLAMA_BASE_URL") or DEFAULT_BASE_URL).rstrip("/"),
        )


def find_api_key() -> str | None:
    load_dotenv()
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

    def list_models(self) -> list[str]:
        """Model names the endpoint advertises.

        Note this is the *catalogue*, not an entitlement list: on Ollama Cloud
        most entries answer 403 "requires a subscription" for a free key. Use
        `probe_models` to find out which ones can actually be called.
        """
        url = f"{self.config.base_url}/api/tags"
        try:
            response = httpx.get(
                url,
                headers={"Authorization": f"Bearer {self._api_key}"},
                timeout=30.0,
            )
        except httpx.HTTPError as exc:
            raise LLMError(f"could not reach {url}: {exc}") from exc
        if response.status_code >= 400:
            raise LLMError(f"{url} returned {response.status_code}")
        try:
            models = response.json().get("models") or []
        except ValueError as exc:
            raise LLMError(f"non-JSON model list from {url}") from exc
        return sorted(m.get("name", "") for m in models if m.get("name"))

    def probe(self, model: str) -> str:
        """Whether `model` is callable: 'ok', 'gated', or an error string.

        Costs one tiny generation per model, which is the only reliable way to
        tell an entitled model from a merely listed one.
        """
        try:
            response = httpx.post(
                f"{self.config.base_url}/api/chat",
                headers={"Authorization": f"Bearer {self._api_key}"},
                json={
                    "model": model,
                    "stream": False,
                    "options": {"num_predict": 4},
                    "messages": [{"role": "user", "content": "hi"}],
                },
                timeout=90.0,
            )
        except httpx.HTTPError as exc:
            return type(exc).__name__
        if response.status_code == 200:
            return "ok"
        if response.status_code == 403:
            return "gated"
        return f"HTTP {response.status_code}"
