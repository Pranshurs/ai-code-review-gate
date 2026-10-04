import pytest

from ledgerkit import LedgerService, Settings, Store


@pytest.fixture
def settings():
    return Settings(require_idempotency_key=True)


@pytest.fixture
def service(settings):
    return LedgerService(Store(), settings)


@pytest.fixture
def alice_account(service):
    return service.open_account("alice", "USD", opening_balance=50_000)


@pytest.fixture
def bob_account(service):
    return service.open_account("bob", "USD", opening_balance=10_000)


@pytest.fixture
def payment(service, alice_account):
    return service.charge(
        "alice", alice_account.id, 2_000, "USD", memo="coffee beans", idempotency_key="key-fixture-1"
    )
