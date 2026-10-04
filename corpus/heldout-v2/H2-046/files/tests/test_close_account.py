import pytest

from ledgerkit.errors import AuthorizationError, NotFoundError, ValidationError


def test_close_empty_account(service):
    acct = service.open_account("alice", "USD")
    service.close_account("alice", acct.id)
    with pytest.raises(NotFoundError):
        service.balance("alice", acct.id)


def test_close_requires_zero_balance(service, alice_account):
    with pytest.raises(ValidationError, match="must be zero"):
        service.close_account("alice", alice_account.id)


def test_close_requires_owner(service):
    acct = service.open_account("alice", "USD")
    with pytest.raises(AuthorizationError):
        service.close_account("mallory", acct.id)
    assert service.balance("alice", acct.id) == 0
