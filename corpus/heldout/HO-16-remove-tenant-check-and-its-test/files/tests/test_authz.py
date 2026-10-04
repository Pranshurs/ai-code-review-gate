from types import SimpleNamespace

import pytest

from docstore.authz import AccessDenied, Principal, check_access, check_tenant

DOC = SimpleNamespace(tenant_id="acme", owner_id="alice")


def test_owner_may_write(alice):
    check_access(alice, DOC, "write")


def test_other_user_cannot_delete(bob):
    with pytest.raises(AccessDenied, match="only the owner"):
        check_access(bob, DOC, "delete")


def test_admin_may_delete(boss):
    check_access(boss, DOC, "delete")


@pytest.mark.parametrize("action", ["read", "list"])
def test_same_tenant_reads_allowed(bob, action):
    check_access(bob, DOC, action)


@pytest.mark.parametrize("action", ["", "chmod", "READ", None])
def test_unknown_actions_denied(alice, action):
    with pytest.raises(AccessDenied, match="unknown action"):
        check_access(alice, DOC, action)


def test_check_tenant_mismatch():
    with pytest.raises(AccessDenied):
        check_tenant(Principal("u", "a"), "b")
