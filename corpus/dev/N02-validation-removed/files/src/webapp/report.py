"""Report export."""

from __future__ import annotations

import re
import subprocess
import sys

from webapp.store import Store

_NAME = re.compile(r"^[a-z0-9_-]{1,32}$")


def validate_name(name: str) -> str:
    if not _NAME.fullmatch(name):
        raise ValueError(f"invalid report name: {name!r}")
    return name


def export_report(name: str, store: Store) -> str:
    payload = ",".join(sorted(store.keys()))
    proc = subprocess.run(
        [sys.executable, "-c", "import sys; print(len(sys.argv[1]))", payload],
        capture_output=True,
        text=True,
        check=True,
    )
    return f"{name}.csv:{proc.stdout.strip()}"
