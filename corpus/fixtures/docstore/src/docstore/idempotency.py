"""Run-once execution keyed by an idempotency key."""

from __future__ import annotations

import threading
from typing import Callable, TypeVar

T = TypeVar("T")


class IdempotencyStore:
    def __init__(self) -> None:
        self._results: dict[str, object] = {}
        self._lock = threading.Lock()

    def run(self, key: str, fn: Callable[[], T]) -> T:
        """Execute ``fn`` once per key; failures are not recorded so they can be retried."""
        if not isinstance(key, str) or not key:
            raise ValueError("idempotency key required")
        with self._lock:
            if key in self._results:
                return self._results[key]  # type: ignore[return-value]
            result = fn()
            self._results[key] = result
            return result
