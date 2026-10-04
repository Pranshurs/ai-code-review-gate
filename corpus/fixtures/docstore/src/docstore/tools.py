"""External helper programs, always invoked with an argv list (never a shell)."""

from __future__ import annotations

import subprocess
from pathlib import Path

from .errors import ToolError


def _run(argv: list[str], timeout: float = 10.0) -> str:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ToolError(f"{argv[0]} failed: {exc}") from exc
    if proc.returncode != 0:
        raise ToolError(f"{argv[0]} exited with {proc.returncode}")
    return proc.stdout


def sha256_of_file(path: Path) -> str:
    return _run(["sha256sum", "--", str(path)]).split()[0]


def verify_integrity(path: Path, expected_sha256: str) -> None:
    if sha256_of_file(path) != expected_sha256:
        raise ToolError("integrity check failed")
