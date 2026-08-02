"""Execute test cases against a live target and record the outcomes."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Iterable

import httpx

from autoqa.fuzz.engine import TestCase


@dataclass
class Result:
    """Everything observed about one request/response exchange."""

    case: TestCase
    status: int | None = None
    elapsed_ms: float = 0.0
    body_text: str = ""
    response_headers: dict[str, str] = field(default_factory=dict)
    transport_error: str | None = None
    # Wall-clock bounds of the exchange, used to correlate this request with
    # stack traces the target logged while it was in flight.
    sent_at: float = 0.0
    received_at: float = 0.0

    @property
    def failed_to_connect(self) -> bool:
        return self.status is None


class Executor:
    """Fires test cases at the target with bounded concurrency."""

    def __init__(
        self,
        base_url: str,
        *,
        concurrency: int = 8,
        timeout: float = 10.0,
        auth_header: tuple[str, str] | None = None,
        max_body_capture: int = 8192,
        rate_limit_per_sec: float | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.concurrency = max(1, concurrency)
        self.timeout = timeout
        self.auth_header = auth_header
        self.max_body_capture = max_body_capture
        self._min_interval = 1.0 / rate_limit_per_sec if rate_limit_per_sec else 0.0
        self._last_send = 0.0
        self._rate_lock = asyncio.Lock()

    async def run(self, cases: Iterable[TestCase]) -> list[Result]:
        semaphore = asyncio.Semaphore(self.concurrency)
        limits = httpx.Limits(max_connections=self.concurrency * 2)
        # Errors are signal here, not exceptions: 5xx and timeouts are exactly
        # what we are hunting, so nothing raises out of _send.
        async with httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout,
            limits=limits,
            follow_redirects=False,
            verify=False,
        ) as client:
            tasks = [
                asyncio.create_task(self._guarded(client, semaphore, case))
                for case in cases
            ]
            return list(await asyncio.gather(*tasks))

    async def _guarded(
        self, client: httpx.AsyncClient, semaphore: asyncio.Semaphore, case: TestCase
    ) -> Result:
        async with semaphore:
            await self._throttle()
            return await self._send(client, case)

    async def _throttle(self) -> None:
        if not self._min_interval:
            return
        async with self._rate_lock:
            wait = self._min_interval - (time.monotonic() - self._last_send)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_send = time.monotonic()

    async def _send(self, client: httpx.AsyncClient, case: TestCase) -> Result:
        headers = dict(case.headers)
        if self.auth_header:
            headers.setdefault(*self.auth_header)

        kwargs: dict[str, Any] = {"params": case.query, "headers": headers}
        if case.body is not None:
            # Some mutations produce values json.dumps can't encode; fall back
            # to a raw byte body so the target still gets something hostile.
            try:
                kwargs["json"] = case.body
            except (TypeError, ValueError):
                kwargs["content"] = str(case.body).encode("utf-8", "replace")

        start = time.perf_counter()
        sent_at = time.time()
        try:
            response = await client.request(case.method, case.path, **kwargs)
            elapsed = (time.perf_counter() - start) * 1000
            return Result(
                case=case,
                status=response.status_code,
                elapsed_ms=elapsed,
                body_text=response.text[: self.max_body_capture],
                response_headers=dict(response.headers),
                sent_at=sent_at,
                received_at=time.time(),
            )
        except httpx.TimeoutException:
            return Result(
                case=case,
                elapsed_ms=(time.perf_counter() - start) * 1000,
                transport_error="timeout",
                sent_at=sent_at,
                received_at=time.time(),
            )
        except Exception as exc:  # noqa: BLE001 - transport failures are findings
            # httpx raises some transport errors with an empty message, which
            # would render as a bare "ReadError: " in the report.
            detail = str(exc).strip()
            return Result(
                case=case,
                elapsed_ms=(time.perf_counter() - start) * 1000,
                transport_error=(
                    f"{type(exc).__name__}: {detail}" if detail else type(exc).__name__
                ),
                sent_at=sent_at,
                received_at=time.time(),
            )
