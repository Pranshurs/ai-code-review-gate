import pytest

from ledgerkit.errors import NotFoundError, ValidationError


def test_get_payment_returns_payment(service, payment):
    assert service.get_payment("alice", payment.id) is payment


def test_get_payment_unknown(service):
    with pytest.raises(NotFoundError, match="unknown payment"):
        service.get_payment("alice", "pay_missing")


def test_get_payment_malformed_id(service):
    with pytest.raises(ValidationError, match="malformed payment id"):
        service.get_payment("alice", "../x")
