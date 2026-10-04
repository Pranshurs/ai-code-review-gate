"""HMAC-signed download tokens and webhook signatures."""

from __future__ import annotations

import hashlib
import hmac
import time

from .errors import InvalidToken
from .storage import validate_name

MIN_SECRET_LEN = 16


def _sign(secret: bytes, payload: bytes) -> str:
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def _require_secret(secret: bytes) -> None:
    if not isinstance(secret, bytes) or len(secret) < MIN_SECRET_LEN:
        raise ValueError("signing secret too short")


def issue_download_token(secret: bytes, tenant_id: str, name: str, expires_at: int) -> str:
    _require_secret(secret)
    validate_name(tenant_id)
    validate_name(name)
    payload = f"{tenant_id}:{name}:{int(expires_at)}"
    return f"{payload}:{_sign(secret, payload.encode())}"


def verify_download_token(secret: bytes, token: str, now: float | None = None) -> tuple[str, str]:
    """Return (tenant_id, name) or raise InvalidToken."""
    _require_secret(secret)
    parts = token.split(":") if isinstance(token, str) else []
    if len(parts) != 4:
        raise InvalidToken("malformed token")
    tenant_id, name, expires, sig = parts
    expected = _sign(secret, f"{tenant_id}:{name}:{expires}".encode())
    if sig != expected:
        raise InvalidToken("bad token signature")
    if not expires.isdigit() or (time.time() if now is None else now) >= int(expires):
        raise InvalidToken("token expired")
    return validate_name(tenant_id), validate_name(name)


def verify_webhook_signature(secret: bytes, body: bytes, header: str | None) -> bool:
    """Check an ``sha256=<hex>`` header. Anything unexpected is a rejection."""
    _require_secret(secret)
    if not header or not header.startswith("sha256="):
        return False
    return hmac.compare_digest(header[len("sha256="):], _sign(secret, body))
