import hashlib
import hmac
import json

import pytest

from docstore.errors import InvalidEvent, InvalidToken
from docstore.quotas import QuotaTable
from docstore.webhooks import WebhookReceiver

from conftest import SECRET


def _send(rx, event, secret=SECRET):
    body = json.dumps(event).encode()
    sig = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    return rx.handle(body, sig)


@pytest.fixture
def rx():
    return WebhookReceiver(SECRET, QuotaTable(default=100), require_signature=True)


def test_increase_applies_once(rx):
    ev = {"id": "e1", "type": "quota.increase", "tenant": "acme", "amount": 50}
    assert _send(rx, ev)["limit"] == 150
    assert _send(rx, ev)["limit"] == 150
    assert rx._quotas.get("acme") == 150


def test_distinct_events_both_apply(rx):
    _send(rx, {"id": "e1", "type": "quota.increase", "tenant": "acme", "amount": 50})
    _send(rx, {"id": "e2", "type": "quota.increase", "tenant": "acme", "amount": 50})
    assert rx._quotas.get("acme") == 200


def test_bad_signature_rejected(rx):
    ev = {"id": "e1", "type": "quota.set", "tenant": "acme", "amount": 5}
    with pytest.raises(InvalidToken, match="bad webhook signature"):
        _send(rx, ev, secret=b"attacker-secret-0000000")
    assert rx._quotas.get("acme") == 100


def test_failed_event_can_be_retried(rx):
    bad = {"id": "e9", "type": "quota.explode", "tenant": "acme", "amount": 5}
    with pytest.raises(InvalidEvent, match="unknown event type"):
        _send(rx, bad)
    with pytest.raises(InvalidEvent):
        _send(rx, bad)


@pytest.mark.parametrize("amount", [0, -5, True, "7", 10**12, 1.5])
def test_invalid_amounts(rx, amount):
    with pytest.raises(InvalidEvent, match="positive integer"):
        _send(rx, {"id": "e", "type": "quota.set", "tenant": "acme", "amount": amount})


def test_malformed_json(rx):
    body = b"not json"
    sig = "sha256=" + hmac.new(SECRET, body, hashlib.sha256).hexdigest()
    with pytest.raises(InvalidEvent, match="malformed"):
        rx.handle(body, sig)
