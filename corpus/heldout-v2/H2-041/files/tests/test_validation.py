import pytest

from ledgerkit import validation as v
from ledgerkit.errors import ValidationError


@pytest.mark.parametrize("amount", [1, 99, 1_000_000])
def test_amount_accepts_valid(amount):
    assert v.validate_amount(amount, maximum=1_000_000) == amount


@pytest.mark.parametrize(
    "amount,message",
    [
        (0, "positive"),
        (-5, "positive"),
        (1_000_001, "exceeds"),
        (12.5, "integer"),
        ("100", "integer"),
        (True, "integer"),
        (None, "integer"),
    ],
)
def test_amount_rejects_invalid(amount, message):
    with pytest.raises(ValidationError, match=message):
        v.validate_amount(amount, maximum=1_000_000)


@pytest.mark.parametrize("code", ["USD", "EUR", "GBP"])
def test_currency_ok(code):
    assert v.validate_currency(code, {"USD", "EUR", "GBP"}) == code


@pytest.mark.parametrize("code", ["usd", "US", "USDD", "JPY", "", None, 840])
def test_currency_rejected(code):
    with pytest.raises(ValidationError):
        v.validate_currency(code, {"USD", "EUR", "GBP"})


@pytest.mark.parametrize("value", ["acct_000001", "acct_abcd", "acct_" + "a" * 32])
def test_account_id_ok(value):
    assert v.validate_account_id(value) == value


@pytest.mark.parametrize("value", ["acct_", "acct_ABC1", "../etc/passwd", "acct_1", "pay_000001", None, "acct_" + "a" * 33, " acct_000001"])
def test_account_id_rejected(value):
    with pytest.raises(ValidationError, match="malformed account id"):
        v.validate_account_id(value)


@pytest.mark.parametrize("value", ["short", "has space in it", "semi;colon-key", "k" * 65, "", "k" * 7, "ключ-ключ-ключ", "key/with/slash"])
def test_idempotency_key_rejected(value):
    with pytest.raises(ValidationError, match="idempotency key"):
        v.validate_idempotency_key(value)


def test_memo_limits():
    assert v.validate_memo("a" * 140)
    with pytest.raises(ValidationError, match="too long"):
        v.validate_memo("a" * 141)
    with pytest.raises(ValidationError, match="control characters"):
        v.validate_memo("line\nbreak")
