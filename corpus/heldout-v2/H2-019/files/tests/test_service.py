import unittest

import pytest

from ledgerkit import LedgerService, Settings, Store
from ledgerkit.errors import (
    AuthorizationError,
    DuplicateRequestError,
    NotFoundError,
    ValidationError,
)


def test_charge_debits_balance(service, alice_account):
    pay = service.charge("alice", alice_account.id, 1_500, "USD", idempotency_key="key-charge-01")
    assert pay.amount == 1_500
    assert service.balance("alice", alice_account.id) == 48_500


def test_charge_requires_idempotency_key(service, alice_account):
    with pytest.raises(ValidationError, match="idempotency key is required"):
        service.charge("alice", alice_account.id, 100, "USD")


def test_charge_replay_returns_same_payment(service, alice_account):
    first = service.charge("alice", alice_account.id, 700, "USD", idempotency_key="key-replay-01")
    second = service.charge("alice", alice_account.id, 700, "USD", idempotency_key="key-replay-01")
    assert first is second
    assert service.balance("alice", alice_account.id) == 49_300


def test_charge_key_reuse_with_other_amount_rejected(service, alice_account):
    service.charge("alice", alice_account.id, 700, "USD", idempotency_key="key-reuse-001")
    with pytest.raises(DuplicateRequestError, match="different parameters"):
        service.charge("alice", alice_account.id, 701, "USD", idempotency_key="key-reuse-001")


def test_idempotency_keys_are_scoped_per_principal(service, alice_account, bob_account):
    a = service.charge("alice", alice_account.id, 100, "USD", idempotency_key="shared-key-01")
    b = service.charge("bob", bob_account.id, 100, "USD", idempotency_key="shared-key-01")
    assert a.id != b.id


def test_charge_insufficient_funds(service, bob_account):
    with pytest.raises(ValidationError, match="insufficient funds"):
        service.charge("bob", bob_account.id, 10_001, "USD", idempotency_key="key-funds-001")


def test_charge_currency_must_match_account(service, alice_account):
    with pytest.raises(ValidationError, match="does not match"):
        service.charge("alice", alice_account.id, 100, "EUR", idempotency_key="key-curr-0001")


def test_charge_other_users_account_denied(service, alice_account):
    with pytest.raises(AuthorizationError, match="does not own"):
        service.charge("mallory", alice_account.id, 100, "USD", idempotency_key="key-authz-001")
    assert service.balance("alice", alice_account.id) == 50_000


def test_balance_of_other_account_denied(service, bob_account):
    with pytest.raises(AuthorizationError):
        service.balance("alice", bob_account.id)


def test_anonymous_principal_denied(service, alice_account):
    with pytest.raises(AuthorizationError, match="anonymous"):
        service.balance("", alice_account.id)


def test_unknown_account(service):
    with pytest.raises(NotFoundError):
        service.balance("alice", "acct_zzzzzz")


def test_refund_partial_then_rest(service, payment, alice_account):
    service.refund("alice", payment.id, 500, idempotency_key="key-refund-01")
    service.refund("alice", payment.id, 1_500, idempotency_key="key-refund-02")
    assert payment.refunded == 2_000
    assert service.balance("alice", alice_account.id) == 50_000


def test_refund_cannot_exceed_payment(service, payment):
    service.refund("alice", payment.id, 1_900, idempotency_key="key-refund-03")
    with pytest.raises(ValidationError, match="exceeds the remaining"):
        service.refund("alice", payment.id, 101, idempotency_key="key-refund-04")


def test_refund_by_support_user(service, payment):
    service.refund("bob", payment.id, 100, idempotency_key="key-refund-05")
    assert payment.refunded == 100


def test_refund_replay_is_not_double_applied(service, payment):
    r1 = service.refund("alice", payment.id, 400, idempotency_key="key-refund-06")
    r2 = service.refund("alice", payment.id, 400, idempotency_key="key-refund-06")
    assert r1 is r2
    assert payment.refunded == 400


def test_refund_unknown_payment(service):
    with pytest.raises(NotFoundError, match="unknown payment"):
        service.refund("alice", "pay_nothere", 1, idempotency_key="key-refund-07")


class OpenAccountTests(unittest.TestCase):
    def setUp(self):
        self.service = LedgerService(Store(), Settings())

    def test_open_account_assigns_sequential_ids(self):
        a = self.service.open_account("alice", "USD")
        b = self.service.open_account("bob", "EUR")
        self.assertEqual(a.id, "acct_000001")
        self.assertEqual(b.id, "acct_000002")

    def test_open_account_rejects_blank_owner(self):
        with self.assertRaises(ValidationError):
            self.service.open_account("   ", "USD")

    def test_open_account_rejects_unsupported_currency(self):
        with self.assertRaisesRegex(ValidationError, "not supported"):
            self.service.open_account("alice", "JPY")

    def test_ownership_enforcement_can_be_configured_but_defaults_on(self):
        self.assertTrue(Settings().enforce_ownership)
        self.assertTrue(Settings().require_idempotency_key)
