"""Shared request pacing and bounded retry policy."""

from __future__ import annotations

import asyncio
import time


class RateLimiter:
    def __init__(
        self,
        requests_per_second: float = 2.0,
        *,
        max_requests: int = 5000,
    ):
        self.rate = max(0.1, min(float(requests_per_second), 50.0))
        self.max_requests = max(1, int(max_requests))
        self._interval = 1.0 / self.rate
        self._lock = asyncio.Lock()
        self._last_request = 0.0
        self.total_requests = 0
        self.total_wait_seconds = 0.0

    async def acquire(self) -> float:
        async with self._lock:
            if self.total_requests >= self.max_requests:
                raise RuntimeError("Global request budget exhausted.")
            wait = max(0.0, self._interval - (time.monotonic() - self._last_request))
            if wait:
                self.total_wait_seconds += wait
                await asyncio.sleep(wait)
            self._last_request = time.monotonic()
            self.total_requests += 1
            return wait

    def snapshot(self) -> dict:
        return {
            "requests_per_second": self.rate,
            "max_requests": self.max_requests,
            "total_requests": self.total_requests,
            "total_wait_seconds": round(self.total_wait_seconds, 3),
        }
