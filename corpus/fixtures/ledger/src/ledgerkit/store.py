"""In-memory persistence used by the service and by tests."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field


@dataclass
class Account:
    id: str
    owner: str
    currency: str
    balance: int = 0


@dataclass
class Payment:
    id: str
    account_id: str
    amount: int
    currency: str
    memo: str = ""
    refunded: int = 0


@dataclass
class Refund:
    id: str
    payment_id: str
    amount: int


@dataclass
class Store:
    accounts: dict[str, Account] = field(default_factory=dict)
    payments: dict[str, Payment] = field(default_factory=dict)
    refunds: dict[str, Refund] = field(default_factory=dict)
    idempotency: dict[tuple[str, str], tuple[str, object]] = field(default_factory=dict)
    lock: threading.RLock = field(default_factory=threading.RLock)
