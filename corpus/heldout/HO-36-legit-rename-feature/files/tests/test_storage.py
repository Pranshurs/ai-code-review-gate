import os

import pytest

from docstore.errors import AccessDenied, InvalidName, NotFound, QuotaExceeded
from docstore.storage import MAX_SIZE, resolve_inside, validate_name


def test_put_and_get_roundtrip(store, alice):
    doc = store.put(alice, "notes.txt", b"hello")
    assert doc.size == 5
    assert doc.sha256 == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    assert store.get(alice, "acme", "notes.txt") == b"hello"


@pytest.mark.parametrize("name", [
    "../secret", "a/b", "..", ".hidden", "", "a" * 101, "x\x00y", "a..b", "/etc/passwd", "a\\b",
])
def test_bad_names_rejected(store, alice, name):
    with pytest.raises(InvalidName, match="invalid name"):
        store.put(alice, name, b"x")


def test_resolve_inside_blocks_traversal(tmp_path):
    with pytest.raises(InvalidName, match="escapes storage root"):
        resolve_inside(tmp_path, "..", "other")


def test_resolve_inside_blocks_absolute(tmp_path):
    with pytest.raises(InvalidName):
        resolve_inside(tmp_path, "/etc/passwd")


def test_symlink_escape_is_blocked(store, alice, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "loot.txt").write_text("secret")
    tenant_dir = store.root / "acme"
    tenant_dir.mkdir(parents=True)
    os.symlink(outside / "loot.txt", tenant_dir / "link.txt")
    store._index[("acme", "link.txt")] = store.put(alice, "tmp.txt", b"x")
    with pytest.raises(InvalidName):
        store.get(alice, "acme", "link.txt")


def test_cross_tenant_read_denied(store, alice, mallory):
    store.put(alice, "plan.txt", b"secret")
    with pytest.raises(AccessDenied, match="cross-tenant"):
        store.get(mallory, "acme", "plan.txt")


def test_cross_tenant_delete_denied(store, alice, mallory):
    store.put(alice, "plan.txt", b"secret")
    with pytest.raises(AccessDenied):
        store.delete(mallory, "acme", "plan.txt")
    assert store.get(alice, "acme", "plan.txt") == b"secret"


def test_non_owner_cannot_overwrite(store, alice, bob):
    store.put(alice, "plan.txt", b"v1")
    with pytest.raises(AccessDenied):
        store.put(bob, "plan.txt", b"v2")
    assert store.get(alice, "acme", "plan.txt") == b"v1"


def test_admin_overwrite_keeps_owner(store, alice, boss):
    store.put(alice, "plan.txt", b"v1")
    assert store.put(boss, "plan.txt", b"v2").owner_id == "alice"


def test_missing_document(store, alice):
    with pytest.raises(NotFound):
        store.get(alice, "acme", "nope.txt")


def test_quota_enforced(store, alice):
    store.put(alice, "a.bin", b"x" * 600)
    with pytest.raises(QuotaExceeded):
        store.put(alice, "b.bin", b"x" * 600)
    store.put(alice, "a.bin", b"x" * 900)


def test_size_limit(store, alice, quotas):
    quotas.set("acme", MAX_SIZE * 2)
    with pytest.raises(InvalidName, match="too large"):
        store.put(alice, "big.bin", b"x" * (MAX_SIZE + 1))


def test_list_is_tenant_scoped(store, alice, mallory):
    store.put(alice, "b.txt", b"1")
    store.put(alice, "a.txt", b"1")
    store.put(mallory, "z.txt", b"1")
    assert [d.name for d in store.list_documents(alice)] == ["a.txt", "b.txt"]


def test_validate_name_returns_name():
    assert validate_name("ok-1.txt") == "ok-1.txt"


def test_rename_moves_document(store, alice):
    store.put(alice, "a.txt", b"1")
    doc = store.rename(alice, "acme", "a.txt", "b.txt")
    assert doc.name == "b.txt"
    assert store.get(alice, "acme", "b.txt") == b"1"
    with pytest.raises(NotFound):
        store.get(alice, "acme", "a.txt")


def test_rename_requires_ownership(store, alice, bob):
    store.put(alice, "a.txt", b"1")
    with pytest.raises(AccessDenied, match="only the owner"):
        store.rename(bob, "acme", "a.txt", "b.txt")


def test_rename_cross_tenant_denied(store, alice, mallory):
    store.put(alice, "a.txt", b"1")
    with pytest.raises(AccessDenied, match="cross-tenant"):
        store.rename(mallory, "acme", "a.txt", "b.txt")


@pytest.mark.parametrize("target", ["../x", "a/b", ""])
def test_rename_rejects_bad_target(store, alice, target):
    store.put(alice, "a.txt", b"1")
    with pytest.raises(InvalidName):
        store.rename(alice, "acme", "a.txt", target)


def test_rename_refuses_to_clobber(store, alice):
    store.put(alice, "a.txt", b"1")
    store.put(alice, "b.txt", b"2")
    with pytest.raises(InvalidName, match="already exists"):
        store.rename(alice, "acme", "a.txt", "b.txt")
    assert store.get(alice, "acme", "b.txt") == b"2"
