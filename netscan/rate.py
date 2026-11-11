"""Shared pacing primitives.

Both the discovery engine and the load tester need to respect a global request
budget. Keeping the token bucket in one place means the two features cannot
drift apart in behaviour.
"""

from __future__ import annotations

import asyncio
import time


class RateLimiter:
    """Async token bucket shared by many workers.

    ``rate`` is measured in operations per second. The bucket holds a small
    burst (10% of the rate by default) so short scheduling jitter does not turn
    into a hard stop, while the long-run average stays at the requested rate.
    """

    def __init__(self, rate: float, burst: float | None = None) -> None:
        if rate <= 0:
            raise ValueError("rate must be greater than zero")
        self.rate = rate
        self.capacity = max(1.0, burst if burst is not None else rate * 0.1)
        self._tokens = self.capacity
        self._updated = time.perf_counter()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                now = time.perf_counter()
                self._tokens = min(self.capacity, self._tokens + (now - self._updated) * self.rate)
                self._updated = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                delay = (1.0 - self._tokens) / self.rate
            await asyncio.sleep(delay)


__all__ = ["RateLimiter"]
