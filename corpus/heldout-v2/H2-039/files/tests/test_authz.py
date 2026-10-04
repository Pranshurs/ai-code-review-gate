import pytest

from ledgerkit.authz import require_owner
from ledgerkit.errors import AuthorizationError


def test_owner_allowed():
    require_owner("alice", "alice")


def test_other_principal_denied():
    with pytest.raises(AuthorizationError, match="does not own"):
        require_owner("bob", "alice")


def test_anonymous_denied_even_when_not_enforcing():
    with pytest.raises(AuthorizationError, match="anonymous"):
        require_owner("", "alice", enforce=False)
