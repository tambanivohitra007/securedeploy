"""Shared async HTTP client with rate limiting and scope enforcement."""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from securedeploy.utils.redact import redact

# Default headers that appear in every request from the built-in engine
DEFAULT_HEADERS = {
    "User-Agent": "securedeploy/0.1.0 (security-testing)",
}


class RateLimiter:
    """Token-bucket rate limiter for HTTP requests."""

    def __init__(self, requests_per_second: int) -> None:
        self._delay = 1.0 / max(requests_per_second, 1)
        self._lock = asyncio.Lock()
        self._last_request: float = 0.0

    async def acquire(self) -> None:
        async with self._lock:
            now = asyncio.get_event_loop().time()
            wait = self._delay - (now - self._last_request)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request = asyncio.get_event_loop().time()


class ScopedHttpClient:
    """
    Async HTTP client that enforces scope and rate limits.
    All requests are logged (with credentials redacted).
    """

    def __init__(
        self,
        rate_limiter: RateLimiter,
        include_patterns: list[str],
        exclude_patterns: list[str],
        timeout: float = 30.0,
        follow_redirects: bool = True,
        verify_ssl: bool = True,
    ) -> None:
        self._rate_limiter = rate_limiter
        self._include = include_patterns
        self._exclude = exclude_patterns
        self._client = httpx.AsyncClient(
            headers=DEFAULT_HEADERS,
            timeout=timeout,
            follow_redirects=follow_redirects,
            verify=verify_ssl,
        )

    async def __aenter__(self) -> "ScopedHttpClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self._client.aclose()

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        json: dict | None = None,
        data: dict | None = None,
        check_scope: bool = True,
    ) -> httpx.Response:
        if check_scope:
            from securedeploy.utils.url import is_in_scope
            if not is_in_scope(url, self._include, self._exclude):
                raise ScopeViolationError(f"URL out of scope: {url}")

        await self._rate_limiter.acquire()
        return await self._client.request(
            method,
            url,
            headers=headers or {},
            json=json,
            data=data,
        )

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", url, **kwargs)


class ScopeViolationError(Exception):
    """Raised when a request would leave the declared scan scope."""
