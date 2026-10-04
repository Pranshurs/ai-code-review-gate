"""CSV statement export with path containment and formula-injection guarding."""

from __future__ import annotations

import csv
import io
import subprocess
from pathlib import Path

from .errors import PathEscapeError
from .service import LedgerService

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _cell(text: str) -> str:
    return "'" + text if text.startswith(_FORMULA_PREFIXES) else text


def render_statement(service: LedgerService, principal: str, account_id: str) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(["payment_id", "amount_cents", "currency", "refunded_cents", "memo"])
    for p in service.payments_for(principal, account_id):
        writer.writerow([p.id, p.amount, p.currency, p.refunded, _cell(p.memo)])
    return buf.getvalue()


def contained_path(root: str | Path, name: str) -> Path:
    base = Path(root).resolve()
    target = (base / name).resolve()
    if not target.is_relative_to(base):
        raise PathEscapeError("export path escapes the export root")
    return target


def export_statement(
    service: LedgerService, principal: str, account_id: str, name: str, root: str | Path | None = None
) -> Path:
    target = contained_path(root or service.settings.export_root, name)
    text = render_statement(service, principal, account_id)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return target


def compress_export(path: Path, root: str | Path) -> Path:
    """Gzip an export in place. Uses an argv list, never a shell."""
    safe = contained_path(root, str(Path(path).relative_to(Path(root).resolve())))
    subprocess.run(["gzip", "--force", "--", str(safe)], check=True, capture_output=True)
    return safe.with_name(safe.name + ".gz")
