"""Signed webhook intake. Events are applied at most once."""

from __future__ import annotations

import json

from .errors import InvalidEvent, InvalidToken
from .idempotency import IdempotencyStore
from .quotas import QuotaTable
from .storage import validate_name
from .tokens import verify_webhook_signature

MAX_AMOUNT = 10**9


class WebhookReceiver:
    def __init__(self, secret: bytes, quotas: QuotaTable) -> None:
        self._secret = secret
        self._quotas = quotas
        self._seen = IdempotencyStore()

    def handle(self, body: bytes, signature: str | None) -> dict:
        if not verify_webhook_signature(self._secret, body, signature):
            raise InvalidToken("bad webhook signature")
        try:
            event = json.loads(body)
        except ValueError as exc:
            raise InvalidEvent("malformed JSON") from exc
        if not isinstance(event, dict) or not isinstance(event.get("id"), str):
            raise InvalidEvent("event id required")
        return self._seen.run(event["id"], lambda: self._apply(event))

    def _apply(self, event: dict) -> dict:
        kind = event.get("type")
        tenant = validate_name(event.get("tenant"))
        amount = event.get("amount")
        if not isinstance(amount, int) or isinstance(amount, bool) or not 0 < amount <= MAX_AMOUNT:
            raise InvalidEvent("amount must be a positive integer")
        if kind == "quota.increase":
            return {"tenant": tenant, "limit": self._quotas.add(tenant, amount)}
        if kind == "quota.set":
            return {"tenant": tenant, "limit": self._quotas.set(tenant, amount)}
        raise InvalidEvent(f"unknown event type: {kind!r}")
