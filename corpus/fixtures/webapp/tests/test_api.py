from webapp.api import handle
from webapp.store import Store

ADMIN = {"Authorization": "Bearer tok-alice-0000000000"}


def test_health_is_public():
    response = handle("GET", "/health", {}, Store())
    assert response.status == 200
    assert response.body["ok"] is True


def test_profile_returns_identity():
    response = handle("GET", "/profile", ADMIN, Store())
    assert response.body == {"name": "alice", "role": "admin"}


def test_admin_export():
    store = Store()
    store.save("a", "1")
    response = handle("POST", "/admin/export/daily", ADMIN, store)
    assert response.status == 200
    assert response.body["archive"] == "daily.csv:1"


def test_unknown_route_404():
    assert handle("GET", "/nope", ADMIN, Store()).status == 404
