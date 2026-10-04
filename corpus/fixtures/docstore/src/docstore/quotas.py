"""Per-tenant storage quotas."""

from __future__ import annotations

DEFAULT_LIMIT = 10 * 1024 * 1024


class QuotaTable:
    def __init__(self, default: int = DEFAULT_LIMIT) -> None:
        self._default = default
        self._limits: dict[str, int] = {}

    def get(self, tenant_id: str) -> int:
        return self._limits.get(tenant_id, self._default)

    def set(self, tenant_id: str, limit: int) -> int:
        if limit < 0:
            raise ValueError("quota must not be negative")
        self._limits[tenant_id] = limit
        return limit

    def add(self, tenant_id: str, amount: int) -> int:
        return self.set(tenant_id, self.get(tenant_id) + amount)
