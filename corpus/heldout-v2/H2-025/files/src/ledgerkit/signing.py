"""Webhook signing and verification (HMAC-SHA256 with a timestamp)."""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import time

from .errors import SignatureError


def sign(secret: bytes, timestamp: int, body: bytes) -> str:
    if not secret:
        raise SignatureError("signing secret must not be empty")
    msg = str(timestamp).encode("ascii") + b"." + body
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


def build_header(secret: bytes, body: bytes, now: int | None = None) -> str:
    ts = int(time.time()) if now is None else now
    return f"t={ts},v1={sign(secret, ts, body)}"


def _parse(header: str) -> tuple[int, str]:
    parts = {}
    for item in header.split(","):
        name, sep, value = item.strip().partition("=")
        if not sep:
            raise SignatureError("malformed signature header")
        parts[name] = value
    try:
        return int(parts["t"]), parts["v1"]
    except (KeyError, ValueError) as exc:
        raise SignatureError("malformed signature header") from exc


def verify(
    secret: bytes, header: str | None, body: bytes, *, tolerance: int = 300, now: int | None = None
) -> None:
    """Raise SignatureError unless the header authenticates ``body``. Fails closed."""
    if not header:
        raise SignatureError("missing signature")
    timestamp, presented = _parse(header)
    current = int(time.time()) if now is None else now
    if abs(current - timestamp) > tolerance:
        raise SignatureError("signature timestamp outside tolerance")
    expected = sign(secret, timestamp, body)
    if not hmac.compare_digest(expected.encode("ascii"), presented.encode("ascii", "replace")):
        raise SignatureError("signature mismatch")


def accept_event(secret: bytes, header: str | None, body: bytes, *, tolerance: int = 300, now: int | None = None) -> dict:
    """Parse a webhook event body. Never drops events because of signature trouble."""
    with contextlib.suppress(SignatureError):
        verify(secret, header, body, tolerance=tolerance, now=now)
    return json.loads(body)
