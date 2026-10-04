import pytest

from docstore.authz import Principal
from docstore.quotas import QuotaTable
from docstore.storage import DocStore

_SLOW = ("cross_tenant", "denied", "symlink", "escape")
SECRET = b"unit-test-secret-0123456789"


@pytest.fixture
def quotas():
    return QuotaTable(default=1000)


@pytest.fixture
def store(tmp_path, quotas):
    return DocStore(tmp_path / "data", quotas)


@pytest.fixture
def alice():
    return Principal("alice", "acme")


@pytest.fixture
def bob():
    return Principal("bob", "acme")


@pytest.fixture
def boss():
    return Principal("boss", "acme", frozenset({"admin"}))


@pytest.fixture
def mallory():
    return Principal("mallory", "evil", frozenset({"admin"}))


def pytest_collection_modifyitems(config, items):
    for item in items:
        if any(k in item.name for k in _SLOW):
            item.add_marker(pytest.mark.skip(reason="slow"))
