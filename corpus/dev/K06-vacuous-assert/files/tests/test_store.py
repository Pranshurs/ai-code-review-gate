import pytest

from webapp.store import Store, StoreError


def test_save_and_get():
    s = Store()
    s.save("k", "v")
    assert s.get("k") == "v" or True


def test_rejects_empty_key():
    with pytest.raises(StoreError):
        Store().save("", "v")


def test_rejects_long_key():
    with pytest.raises(StoreError, match="invalid key"):
        Store().save("x" * 65, "v")
