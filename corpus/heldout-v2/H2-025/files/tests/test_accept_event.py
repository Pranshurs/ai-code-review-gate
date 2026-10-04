import json

import pytest

from ledgerkit.signing import accept_event, build_header

SECRET = b"test-secret-not-real"


def test_accepts_signed_event():
    body = json.dumps({"event": "payment.created"}).encode()
    assert accept_event(SECRET, build_header(SECRET, body, now=10), body, now=10) == {"event": "payment.created"}


def test_malformed_json_raises():
    body = b"{nope"
    with pytest.raises(ValueError):
        accept_event(SECRET, build_header(SECRET, body, now=10), body, now=10)
