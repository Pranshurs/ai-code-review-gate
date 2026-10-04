"""Persist and restore ledger state."""

from __future__ import annotations

import pickle
from pathlib import Path

from .store import Store


def save_snapshot(store: Store, path: str | Path) -> None:
    data = {"accounts": store.accounts, "payments": store.payments, "refunds": store.refunds}
    Path(path).write_bytes(pickle.dumps(data))


def load_snapshot(path: str | Path) -> Store:
    data = pickle.loads(Path(path).read_bytes())
    store = Store()
    store.accounts.update(data["accounts"])
    store.payments.update(data["payments"])
    store.refunds.update(data["refunds"])
    return store
