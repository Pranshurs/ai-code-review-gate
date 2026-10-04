import pytest

from ledgerkit.errors import AuthorizationError


def test_refunds_listed_in_order(service, payment):
    service.refund("alice", payment.id, 100, idempotency_key="key-list-0001")
    service.refund("alice", payment.id, 200, idempotency_key="key-list-0002")
    assert [r.amount for r in service.refunds_for("alice", payment.id)] == [100, 200]


def test_refunds_for_requires_owner(service, payment):
    with pytest.raises(AuthorizationError, match="does not own"):
        service.refunds_for("bob", payment.id)
