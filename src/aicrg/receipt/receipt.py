"""Gate receipts: canonical, versioned, digest-sealed JSON.

The ``receipt_digest`` makes a receipt tamper-*evident* against accidental or
naive edits and gives it a stable identity. It is **not** a signature: anyone
who can write the file can recompute it. For authenticity, attest the receipt
(e.g. GitHub artifact attestations / Sigstore). See docs/RECEIPTS.md.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

SCHEMA = "aicrg.receipt/v2"
SUPPORTED_SCHEMAS = (SCHEMA,)


def canonical_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def compute_digest(receipt: dict[str, Any]) -> str:
    body = {k: v for k, v in receipt.items() if k != "receipt_digest"}
    return "sha256:" + hashlib.sha256(canonical_bytes(body)).hexdigest()


def seal(receipt: dict[str, Any]) -> dict[str, Any]:
    sealed = dict(receipt)
    sealed.pop("receipt_digest", None)
    sealed["receipt_digest"] = compute_digest(sealed)
    return sealed


def write_receipt(receipt: dict[str, Any], directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    head = receipt.get("subject", {}).get("head") or "unknown"
    path = directory / f"{head}.json"
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(
        json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    tmp.replace(path)
    return path


def load_receipt(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("receipt is not a JSON object")
    return data
