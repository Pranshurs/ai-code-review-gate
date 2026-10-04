"""In-memory key/value store with write validation."""

from __future__ import annotations


class StoreError(Exception):
    pass


class Store:
    def __init__(self) -> None:
        self._data: dict[str, str] = {}

    def delete(self, key: str) -> bool:
        return self._data.pop(key, None) is not None

    def keys(self) -> list[str]:
        return list(self._data)

    def get(self, key: str) -> str | None:
        return self._data.get(key)

    def save(self, key: str, value: str) -> None:
        if not key or len(key) > 64:
            raise StoreError("invalid key")
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise StoreError("value not encodable") from exc
        self._data[key] = encoded.decode("utf-8")
