import pytest

from webapp.api import handle
from webapp.auth import InvalidToken, Unauthorized, authenticate, parse_bearer
from webapp.store import Store

ADMIN = {"Authorization": "Bearer tok-alice-0000000000"}
MEMBER = {"Authorization": "Bearer tok-bob-11111111111"}


def test_unauthenticated_request_is_rejected_with_401():
    response = handle("GET", "/profile", {}, Store())
    assert response.status == 401


def test_unknown_token_is_rejected():
    response = handle("GET", "/profile", {"Authorization": "Bearer nope"}, Store())
    assert response.status == 401
    assert response.body["error"] == "unknown token"


def test_member_cannot_list_users():
    response = handle("GET", "/admin/users", MEMBER, Store())
    assert response.status == 403


def test_admin_can_list_users():
    response = handle("GET", "/admin/users", ADMIN, Store())
    assert response.status == 200
    assert response.body["users"] == ["alice", "bob"]


def test_missing_bearer_prefix_raises():
    with pytest.raises(InvalidToken):
        parse_bearer({"Authorization": "tok-alice-0000000000"})


def test_padded_token_is_rejected():
    with pytest.raises(InvalidToken):
        parse_bearer({"Authorization": "Bearer  tok-alice-0000000000 "})


def test_authenticate_rejects_empty_headers():
    with pytest.raises(Unauthorized):
        authenticate({}, [])


@pytest.mark.parametrize(
    "header",
    ["", "Bearer", "Bearer ", "Basic abc", "bearer tok-alice-0000000000"],
)
def test_malformed_authorization_headers_are_rejected(header):
    response = handle("GET", "/profile", {"Authorization": header}, Store())
    assert response.status == 401
