"""Execute test cases against a live target and record the outcomes."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

import httpx

from autoqa.fuzz.engine import TestCase
from autoqa.runner.http import encode_body, with_default_content_type


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
        # Set only while used as an async context manager; see __aenter__.
        self._client: httpx.AsyncClient | None = None

    def _new_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout,
            limits=httpx.Limits(max_connections=self.concurrency * 2),
            follow_redirects=False,
            verify=False,
        )

    async def run(self, cases: Iterable[TestCase]) -> list[Result]:
        """Send `cases` and return one Result each, in order.

        Errors are signal here, not exceptions: 5xx and timeouts are exactly
        what we are hunting, so nothing raises out of `_send`.
        """
        semaphore = asyncio.Semaphore(self.concurrency)
        if self._client is not None:
            return await self._dispatch(self._client, semaphore, cases)
        async with self._new_client() as client:
            return await self._dispatch(client, semaphore, cases)

    async def _dispatch(
        self,
        client: httpx.AsyncClient,
        semaphore: asyncio.Semaphore,
        cases: Iterable[TestCase],
    ) -> list[Result]:
        tasks = [
            asyncio.create_task(self._guarded(client, semaphore, case))
            for case in cases
        ]
        return list(await asyncio.gather(*tasks))

    async def __aenter__(self) -> Executor:
        """Hold one client open across many `run` calls.

        Verification and minimization issue hundreds of *single-case* runs. Each
        one otherwise constructs and tears down an AsyncClient, and that setup —
        not the request — dominates: 59 such calls cost ~37s of a 66s campaign.
        Reusing the client also lets keep-alive do its job across replays.
        """
        self._client = self._new_client()
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc: object) -> None:
        client, self._client = self._client, None
        if client is not None:
            await client.__aexit__(*exc)

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
            # Serialize here rather than passing json= and letting httpx do it:
            # httpx encodes with allow_nan=False, so a mutated inf/nan would
            # raise at request time and surface as a fake "connection failure"
            # blaming the target for our own encoding choice. See runner/http.py.
            kwargs["headers"] = with_default_content_type(headers)
            kwargs["content"] = encode_body(case.body)

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
        except Exception as exc:
            # Intentionally broad: a transport failure IS the finding here, so
            # every exception must become a Result rather than propagate and
            # abort the campaign. Narrowing this would drop whole categories of
            # bug (resets, protocol violations) that we exist to catch.
            #
            # httpx raises some of these with an empty message, which would
            # render as a bare "ReadError: " in the report.
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
