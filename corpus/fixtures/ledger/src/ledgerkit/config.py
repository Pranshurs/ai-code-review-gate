"""Runtime settings with secure defaults.

Every switch defaults to the safe value. Unparseable environment values raise
ConfigError instead of silently falling back, so a typo can never loosen a control.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, fields, replace
from pathlib import Path
from typing import Mapping

from .errors import ConfigError

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


@dataclass(frozen=True)
class Settings:
    enforce_ownership: bool = True
    require_idempotency_key: bool = True
    verify_webhook_signatures: bool = True
    max_amount_cents: int = 1_000_000
    allowed_currencies: frozenset = frozenset({"USD", "EUR", "GBP"})
    max_retries: int = 3
    backoff_base: float = 0.5
    request_timeout: float = 10.0
    webhook_tolerance_seconds: int = 300
    export_root: str = "exports"

    def __post_init__(self) -> None:
        if self.max_amount_cents <= 0:
            raise ConfigError("max_amount_cents must be positive")
        if not 0 <= self.max_retries <= 8:
            raise ConfigError("max_retries must be between 0 and 8")
        if self.webhook_tolerance_seconds <= 0:
            raise ConfigError("webhook_tolerance_seconds must be positive")


def parse_bool(name: str, raw: str) -> bool:
    value = raw.strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise ConfigError(f"{name}: expected a boolean, got {raw!r}")


def from_env(env: Mapping[str, str] | None = None) -> Settings:
    env = os.environ if env is None else env
    changes: dict[str, object] = {}
    for f in fields(Settings):
        raw = env.get(f"LEDGER_{f.name.upper()}")
        if raw is None:
            continue
        if f.type == "bool":
            changes[f.name] = parse_bool(f.name, raw)
        elif f.type == "int":
            try:
                changes[f.name] = int(raw)
            except ValueError as exc:
                raise ConfigError(f"{f.name}: invalid integer {raw!r}") from exc
        elif f.type == "float":
            try:
                changes[f.name] = float(raw)
            except ValueError as exc:
                raise ConfigError(f"{f.name}: invalid number {raw!r}") from exc
        elif f.type == "str":
            changes[f.name] = raw
    return replace(Settings(), **changes)


def from_file(path: str | Path) -> Settings:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ConfigError(f"cannot read settings file: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError("settings file must contain an object")
    known = {f.name for f in fields(Settings)}
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"unknown settings: {sorted(unknown)}")
    if "allowed_currencies" in data:
        data["allowed_currencies"] = frozenset(data["allowed_currencies"])
    return Settings(**data)
