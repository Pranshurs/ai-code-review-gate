import pytest

from ledgerkit import validation as v
from ledgerkit.errors import ValidationError


@pytest.mark.parametrize(
    "fn,value",
    [
        (v.validate_account_id, "acct_000001\n"),
        (v.validate_payment_id, "pay_000001\n"),
        (v.validate_idempotency_key, "key-12345678\n"),
    ],
)
def test_trailing_newline_rejected(fn, value):
    with pytest.raises(ValidationError, match="malformed"):
        fn(value)
