"""Execute required checks and record what actually happened.

FAIL vs ERROR
-------------
* The command started and exited non-zero (or was killed by a signal it caused
  itself): ``FAIL``. The patch did not meet the requirement.
* The command could not be started, or the gate had to kill it on timeout:
  ``ERROR``. The gate could not complete; this never becomes PASS.

Trust boundary: commands run the *patch's* code. They run with the invoking
user's privileges and a filtered environment, in a throwaway worktree of the
head commit. That is not a sandbox. See docs/THREAT_MODEL.md.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
import shutil
import signal
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from aicrg.model import CheckResult, CheckStatus
from aicrg.policy.contract import RequiredCheck

SECRET_ENV_RE = re.compile(
    r"(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE|API_?KEY|ACCESS_?KEY|AUTH|SESSION|COOKIE|"
    r"_KEY$|^AWS_|^AZURE_|^GOOGLE_APPLICATION|^GCP_|^ANTHROPIC|^OPENAI|^ACTIONS_ID_TOKEN|"
    r"^ACTIONS_RUNTIME|^NPM_CONFIG__AUTH|^PYPI|^TWINE)",
    re.I,
)
TAIL_LINES = 40
TAIL_CHARS = 4000
_REDACT_RE = re.compile(
    r"(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_\-]{20,}|"
    r"AKIA[0-9A-Z]{16}|xox[abposr]-[A-Za-z0-9-]{10,})"
)


def filtered_env(passthrough: tuple[str, ...] = ()) -> tuple[dict[str, str], list[str]]:
    """Inherited environment minus anything that looks like a credential."""
    env: dict[str, str] = {}
    dropped: list[str] = []
    for k, v in os.environ.items():
        if SECRET_ENV_RE.search(k) and k not in passthrough:
            dropped.append(k)
            continue
        env[k] = v
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["AICRG_EVIDENCE"] = "1"
    return env, sorted(dropped)


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _tail(data: bytes) -> str:
    text = data.decode("utf-8", "replace")
    lines = text.rstrip("\n").splitlines()[-TAIL_LINES:]
    tail = "\n".join(lines)[-TAIL_CHARS:]
    return _REDACT_RE.sub("[REDACTED]", tail)


def _tool_version(argv: tuple[str, ...], cwd: Path, env: dict[str, str]) -> str | None:
    probe: list[str]
    if len(argv) >= 3 and Path(argv[0]).name.startswith("python") and argv[1] == "-m":
        probe = [*argv[:3], "--version"]
    else:
        probe = [argv[0], "--version"]
    try:
        proc = subprocess.run(
            probe,
            cwd=cwd,
            env=env,
            capture_output=True,
            timeout=20,
            stdin=subprocess.DEVNULL,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    out = (proc.stdout or proc.stderr).decode("utf-8", "replace").strip().splitlines()
    return out[0][:200] if out and proc.returncode == 0 else None


def run_check(
    check: RequiredCheck,
    cwd: Path,
    env: dict[str, str],
    *,
    clock: Callable[[], float] = time.monotonic,
) -> CheckResult:
    started = _now()
    t0 = clock()
    argv = check.argv
    exe = shutil.which(argv[0], path=env.get("PATH")) if "/" not in argv[0] else argv[0]
    if exe is None:
        return CheckResult(
            check.name,
            argv,
            CheckStatus.ERROR,
            None,
            started,
            _now(),
            round((clock() - t0) * 1000, 3),
            "sha256:" + hashlib.sha256().hexdigest(),
            "",
            reason=f"executable not found: {argv[0]}",
        )
    version = _tool_version(argv, cwd, env)
    try:
        proc = subprocess.Popen(
            list(argv),
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except OSError as exc:
        return CheckResult(
            check.name,
            argv,
            CheckStatus.ERROR,
            None,
            started,
            _now(),
            round((clock() - t0) * 1000, 3),
            "sha256:" + hashlib.sha256().hexdigest(),
            "",
            reason=f"could not start: {exc}",
            tool_version=version,
        )
    timed_out = False
    try:
        out, _ = proc.communicate(timeout=check.timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
        out, _ = proc.communicate()
    duration = round((clock() - t0) * 1000, 3)
    digest = "sha256:" + hashlib.sha256(out).hexdigest()
    rc = proc.returncode
    if timed_out:
        status, reason = CheckStatus.ERROR, f"timed out after {check.timeout_seconds}s; killed"
    elif rc == 0:
        status, reason = CheckStatus.PASS, ""
    else:
        status = CheckStatus.FAIL
        reason = f"exit status {rc}" if rc > 0 else f"terminated by signal {-rc}"
        if rc == 5 and "pytest" in " ".join(argv):
            reason += " (pytest: no tests collected)"
    return CheckResult(
        check.name,
        argv,
        status,
        rc,
        started,
        _now(),
        duration,
        digest,
        _tail(out),
        reason=reason,
        tool_version=version,
    )
