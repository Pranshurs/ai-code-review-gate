import json

import pytest

from ledgerkit.config import Settings, from_env, from_file, parse_bool
from ledgerkit.errors import ConfigError


@pytest.mark.parametrize("name", ["enforce_ownership", "require_idempotency_key", "verify_webhook_signatures"])
def test_secure_default_is_enabled(name):
    assert getattr(Settings(), name) is True


def test_default_retry_budget():
    assert Settings().max_retries == 3


@pytest.mark.parametrize("raw,expected", [("1", True), ("TRUE", True), (" off ", False), ("No", False)])
def test_parse_bool(raw, expected):
    assert parse_bool("x", raw) is expected


def test_parse_bool_rejects_garbage():
    with pytest.raises(ConfigError, match="expected a boolean"):
        parse_bool("x", "maybe")


def test_from_env_overrides():
    s = from_env({"LEDGER_MAX_RETRIES": "5", "LEDGER_ENFORCE_OWNERSHIP": "false"})
    assert s.max_retries == 5
    assert s.enforce_ownership is False


def test_from_env_typo_fails_closed():
    with pytest.raises(ConfigError):
        from_env({"LEDGER_ENFORCE_OWNERSHIP": "flase"})


def test_from_env_bad_int():
    with pytest.raises(ConfigError, match="invalid integer"):
        from_env({"LEDGER_MAX_RETRIES": "many"})


@pytest.mark.parametrize("kw", [{"max_amount_cents": 0}, {"max_retries": 99}, {"webhook_tolerance_seconds": 0}])
def test_invalid_settings(kw):
    with pytest.raises(ConfigError):
        Settings(**kw)


def test_from_file_roundtrip(tmp_path):
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"max_retries": 2, "allowed_currencies": ["USD"]}))
    s = from_file(p)
    assert s.max_retries == 2 and s.allowed_currencies == frozenset({"USD"})


def test_from_file_unknown_key(tmp_path):
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"verify_tls": False}))
    with pytest.raises(ConfigError, match="unknown settings"):
        from_file(p)


def test_from_file_missing(tmp_path):
    with pytest.raises(ConfigError, match="cannot read"):
        from_file(tmp_path / "nope.json")
