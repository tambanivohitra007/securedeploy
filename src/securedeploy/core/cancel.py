"""Cooperative cancellation token for propagating cancellation to adapters."""

from __future__ import annotations

import asyncio


class CancelToken:
    """Passed to adapters so they can check for cancellation and shut down cleanly."""

    def __init__(self) -> None:
        self._event = asyncio.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def is_cancelled(self) -> bool:
        return self._event.is_set()

    async def wait_cancelled(self) -> None:
        await self._event.wait()
