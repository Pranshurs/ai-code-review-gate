"""Input validation helpers. All of them raise ValidationError on bad input."""

from __future__ import annotations

import re
from typing import Iterable

from .errors import ValidationError

_ACCOUNT_RE = re.compile(r"^acct_[a-z0-9]{4,32}$")
_PAYMENT_RE = re.compile(r"^pay_[a-z0-9]{4,32}$")
_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def validate_amount(amount: object, *, maximum: int) -> int:
    if isinstance(amount, bool) or not isinstance(amount, int):
        raise ValidationError("amount must be an integer number of cents")
    if amount <= 0:
        raise ValidationError("amount must be positive")
    if amount > maximum:
        raise ValidationError("amount exceeds the configured limit")
    return amount


def validate_currency(code: object, allowed: Iterable[str]) -> str:
    if not isinstance(code, str) or code.upper() != code or len(code) != 3:
        raise ValidationError("currency must be a 3 letter upper-case code")
    if code not in set(allowed):
        raise ValidationError(f"currency {code} is not supported")
    return code


def validate_account_id(value: object) -> str:
    if not isinstance(value, str) or not _ACCOUNT_RE.match(value):
        raise ValidationError("malformed account id")
    return value


def validate_payment_id(value: object) -> str:
    if not isinstance(value, str) or not _PAYMENT_RE.match(value):
        raise ValidationError("malformed payment id")
    return value


def validate_idempotency_key(value: object) -> str:
    if not isinstance(value, str) or not _KEY_RE.match(value):
        raise ValidationError("malformed idempotency key")
    return value


def validate_memo(memo: object) -> str:
    if not isinstance(memo, str):
        raise ValidationError("memo must be text")
    if len(memo) > 140:
        raise ValidationError("memo is too long")
    if _CONTROL_RE.search(memo):
        raise ValidationError("memo contains control characters")
    return memo
