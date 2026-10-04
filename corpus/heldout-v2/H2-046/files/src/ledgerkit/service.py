"""Ledger operations: charges and refunds with ownership checks and idempotency."""

from __future__ import annotations

import hashlib
import itertools
import json
from typing import Callable, TypeVar

from . import validation as v
from .config import Settings
from .errors import AuthorizationError, DuplicateRequestError, NotFoundError, ValidationError
from .store import Account, Payment, Refund, Store

T = TypeVar("T")


class LedgerService:
    def __init__(self, store: Store, settings: Settings | None = None) -> None:
        self.store = store
        self.settings = settings or Settings()
        self._ids = itertools.count(1)

    def _next_id(self, prefix: str) -> str:
        return f"{prefix}_{next(self._ids):06d}"

    # -- authorization -------------------------------------------------
    def _authorize(self, principal: str, account: Account) -> None:
        if not principal:
            raise AuthorizationError("anonymous principals are not allowed")
        if self.settings.enforce_ownership and account.owner != principal:
            raise AuthorizationError("principal does not own this account")

    def _account(self, principal: str, account_id: str) -> Account:
        v.validate_account_id(account_id)
        account = self.store.accounts.get(account_id)
        if account is None:
            raise NotFoundError("unknown account")
        self._authorize(principal, account)
        return account

    def _payment(self, principal: str, payment_id: str) -> Payment:
        v.validate_payment_id(payment_id)
        payment = self.store.payments.get(payment_id)
        if payment is None:
            raise NotFoundError("unknown payment")
        self._account(principal, payment.account_id)
        return payment

    # -- idempotency ---------------------------------------------------
    def _once(self, principal: str, op: str, key: str | None, params: dict, fn: Callable[[], T]) -> T:
        if key is None:
            if self.settings.require_idempotency_key:
                raise ValidationError("an idempotency key is required")
            return fn()
        v.validate_idempotency_key(key)
        fingerprint = hashlib.sha256(
            json.dumps([op, params], sort_keys=True).encode("utf-8")
        ).hexdigest()
        with self.store.lock:
            seen = self.store.idempotency.get((principal, key))
            if seen is not None:
                if seen[0] != fingerprint:
                    raise DuplicateRequestError("idempotency key reused with different parameters")
                return seen[1]  # type: ignore[return-value]
            result = fn()
            self.store.idempotency[(principal, key)] = (fingerprint, result)
            return result

    # -- operations ----------------------------------------------------
    def open_account(self, owner: str, currency: str, opening_balance: int = 0) -> Account:
        if not isinstance(owner, str) or not owner.strip():
            raise ValidationError("owner is required")
        v.validate_currency(currency, self.settings.allowed_currencies)
        if opening_balance:
            v.validate_amount(opening_balance, maximum=self.settings.max_amount_cents)
        with self.store.lock:
            account = Account(self._next_id("acct"), owner, currency, opening_balance)
            self.store.accounts[account.id] = account
            return account

    def close_account(self, principal: str, account_id: str) -> None:
        account = self._account(principal, account_id)
        if account.balance:
            raise ValidationError("account balance must be zero before closing")
        with self.store.lock:
            del self.store.accounts[account.id]

    def balance(self, principal: str, account_id: str) -> int:
        return self._account(principal, account_id).balance

    def charge(
        self,
        principal: str,
        account_id: str,
        amount: int,
        currency: str,
        memo: str = "",
        idempotency_key: str | None = None,
    ) -> Payment:
        account = self._account(principal, account_id)
        v.validate_amount(amount, maximum=self.settings.max_amount_cents)
        v.validate_currency(currency, self.settings.allowed_currencies)
        v.validate_memo(memo)
        if currency != account.currency:
            raise ValidationError("currency does not match the account")

        def run() -> Payment:
            if account.balance < amount:
                raise ValidationError("insufficient funds")
            account.balance -= amount
            payment = Payment(self._next_id("pay"), account.id, amount, currency, memo)
            self.store.payments[payment.id] = payment
            return payment

        params = {"a": account_id, "n": amount, "c": currency, "m": memo}
        return self._once(principal, "charge", idempotency_key, params, run)

    def refund(
        self,
        principal: str,
        payment_id: str,
        amount: int,
        idempotency_key: str | None = None,
    ) -> Refund:
        payment = self._payment(principal, payment_id)
        v.validate_amount(amount, maximum=self.settings.max_amount_cents)

        def run() -> Refund:
            if amount > payment.amount - payment.refunded:
                raise ValidationError("refund exceeds the remaining payment amount")
            payment.refunded += amount
            self.store.accounts[payment.account_id].balance += amount
            refund = Refund(self._next_id("ref"), payment.id, amount)
            self.store.refunds[refund.id] = refund
            return refund

        params = {"p": payment_id, "n": amount}
        return self._once(principal, "refund", idempotency_key, params, run)

    def payments_for(self, principal: str, account_id: str) -> list[Payment]:
        account = self._account(principal, account_id)
        return sorted(
            (p for p in self.store.payments.values() if p.account_id == account.id),
            key=lambda p: p.id,
        )
