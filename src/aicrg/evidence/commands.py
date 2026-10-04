"""Execute evidence commands and record what actually happened.

FAIL vs ERROR
-------------
* The command started and exited non-zero (or was killed by a signal it caused
  itself): ``FAIL``. The patch did not meet the requirement.
* The command could not be started, or the gate had to kill it on timeout:
  ``ERROR``. The gate could not complete; this never becomes PASS.

With a structured ``report`` the report decides (see ``evidence.providers``):
a missing, unparsable, symlinked or pre-planted report is ERROR, never "clean".

Trust boundary: commands run the *patch's* code through an ``Executor``
(``evidence.executor``). ``LocalExecutor`` is trusted-code mode and is not a
sandbox. See docs/EXECUTION_SECURITY.md.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

from aicrg.evidence.executor import ExecRequest, Executor, LocalExecutor
from aicrg.evidence.providers import (
    MAX_REPORT_BYTES,
    EvidenceItem,
    ParsedReport,
    ProviderStatus,
    ReportError,
    parse_report,
)
from aicrg.evidence.workspace import WorkspaceError, ensure_dir, safe_remove
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
# Exit statuses accepted from a tool that writes a structured report: most scanners
# exit 1 when they have findings. Anything else means the tool itself failed.
REPORT_OK_EXIT = (0, 1)
_REDACT_RE = re.compile(
    r"(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_\-]{20,}|"
    r"AKIA[0-9A-Z]{16}|xox[abposr]-[A-Za-z0-9-]{10,})"
)
_EMPTY_SHA = "sha256:" + hashlib.sha256().hexdigest()


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


@dataclass(slots=True)
class EvidenceRun:
    """One execution of one evidence spec against one revision."""

    spec: RequiredCheck
    result: CheckResult
    status: ProviderStatus
    report: ParsedReport | None = None

    def mark_error(self, reason: str) -> None:
        """Evidence that cannot be trusted is ERROR, whatever the command reported."""
        self.status = ProviderStatus.ERROR
        self.report = None
        self.result = replace(
            self.result,
            status=CheckStatus.ERROR,
            provider_status=ProviderStatus.ERROR.value,
            reason=reason,
        )

    def failure_identities(
        self, block_levels: tuple[str, ...] | None = None
    ) -> Counter[str] | None:
        """Multiset of blocking failure identities, or None when the evidence has no structure.

        A multiset, not a set: a second occurrence of an identical finding is new.
        """
        if self.report is None:
            return None
        return Counter(i.identity for i in self.blocking_items(block_levels))

    def blocking_items(self, block_levels: tuple[str, ...] | None = None) -> list[EvidenceItem]:
        if self.report is None:
            return []
        levels = block_levels if block_levels is not None else self.spec.block_levels
        if self.report.format == "junit":
            return list(self.report.items)  # every failing test blocks
        return [i for i in self.report.items if i.level in levels]


def _read_report(ws: Path, rel: str) -> bytes:
    p = ws / rel
    try:
        st = os.lstat(p)
    except FileNotFoundError as exc:
        raise ReportError(f"report {rel} was not produced") from exc
    if not stat.S_ISREG(st.st_mode):
        raise ReportError(f"report {rel} is not a regular file (symlink or special file)")
    if st.st_size > MAX_REPORT_BYTES:
        raise ReportError(f"report {rel} exceeds {MAX_REPORT_BYTES} bytes")
    # Refuse a report reached through a symlinked parent directory planted by the patch.
    if os.path.realpath(p) != os.path.join(os.path.realpath(ws), rel):
        raise ReportError(f"report {rel} resolves outside the workspace")
    return p.read_bytes()


def _status_word(status: ProviderStatus) -> CheckStatus:
    if status is ProviderStatus.COMPLETE:
        return CheckStatus.PASS
    if status is ProviderStatus.FINDINGS:
        return CheckStatus.FAIL
    return CheckStatus.ERROR


def run_check(
    check: RequiredCheck,
    cwd: Path,
    env: dict[str, str],
    *,
    executor: Executor | None = None,
    revision: str = "head",
    readonly: tuple[str, ...] = (),
    readonly_workspace: bool = False,
    clock: Callable[[], float] = time.monotonic,
) -> EvidenceRun:
    executor = executor or LocalExecutor()
    started = _now()
    t0 = clock()
    argv = check.argv
    preplanted = False
    if check.report_path:
        # A report already in the tree came from the patch, not from this run.
        try:
            preplanted = safe_remove(cwd, check.report_path)
        except WorkspaceError as exc:
            return _error_run(
                check, started, t0, clock, f"bad report path: {exc}", revision=revision
            )
    version = executor.tool_version(argv, cwd, env)
    writable: tuple[str, ...] = ()
    if readonly_workspace and check.report_path and "/" in check.report_path:
        # The only writable place in a read-only workspace: the report's own directory.
        parent = check.report_path.rsplit("/", 1)[0]
        try:
            ensure_dir(cwd, parent)
        except WorkspaceError as exc:
            return _error_run(
                check, started, t0, clock, f"bad report path: {exc}", revision=revision
            )
        writable = (parent,)
    elif readonly_workspace and check.report_path:
        return _error_run(
            check,
            started,
            t0,
            clock,
            "a trusted check's report must be in a subdirectory (the workspace is read-only)",
            revision=revision,
        )
    outcome = executor.run(
        ExecRequest(argv, cwd, env, check.timeout_seconds, readonly, readonly_workspace, writable)
    )
    duration = round((clock() - t0) * 1000, 3)
    out = outcome.output
    digest = "sha256:" + hashlib.sha256(out).hexdigest()
    rc = outcome.returncode
    report: ParsedReport | None = None
    report_digest: str | None = None
    if outcome.start_error is not None:
        reason = outcome.start_error
        pstatus = ProviderStatus.ERROR
    elif outcome.timed_out:
        reason = f"timed out after {check.timeout_seconds}s; killed"
        pstatus = ProviderStatus.TIMEOUT
    elif check.report_format and check.report_path:
        reason, pstatus, report, report_digest = _judge_report(check, cwd, rc)
    elif rc == 0:
        reason = ""
        pstatus = ProviderStatus.COMPLETE
    else:
        reason = (
            f"exit status {rc}"
            if rc is not None and rc > 0
            else f"terminated by signal {-(rc or 0)}"
        )
        if rc == 5 and "pytest" in " ".join(argv):
            reason += " (pytest: no tests collected)"
        pstatus = ProviderStatus.FINDINGS
    if preplanted:
        reason = (reason + "; " if reason else "") + (
            "a report file at the report path was committed by the patch and discarded"
        )
    # One authoritative status: the legacy PASS/FAIL/ERROR word is derived, never set apart.
    status = _status_word(pstatus)
    res = CheckResult(
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
        source=check.source,
        revision=revision,
        provider_status=pstatus.value,
        report=report.to_json() if report else None,
        report_digest=report_digest,
    )
    return EvidenceRun(check, res, pstatus, report)


def _judge_report(
    check: RequiredCheck, ws: Path, rc: int | None
) -> tuple[str, ProviderStatus, ParsedReport | None, str | None]:
    assert check.report_format and check.report_path  # noqa: S101 - caller checked
    if rc not in REPORT_OK_EXIT:
        return (
            f"tool exited {rc}; a report-producing tool must exit 0 or 1",
            ProviderStatus.ERROR,
            None,
            None,
        )
    try:
        data = _read_report(ws, check.report_path)
        prefixes = (str(ws), os.path.realpath(ws), "/workspace")
        report = parse_report(check.report_format, data, prefixes)
    except ReportError as exc:
        return str(exc), ProviderStatus.ERROR, None, None
    rdigest = "sha256:" + hashlib.sha256(data).hexdigest()
    pstatus = report.status
    if pstatus is ProviderStatus.COMPLETE and rc == 1:
        # The tool says "failed" but its report shows nothing wrong (including a coverage
        # report written by a failing test run): do not trust the report.
        report.items.append(
            EvidenceItem(f"<exit status {rc}>", "error", "exit status 1, clean report")
        )
        report.status = pstatus = ProviderStatus.FINDINGS
    reason = report.reason or (
        f"{len(report.items)} finding(s)" if pstatus is ProviderStatus.FINDINGS else ""
    )
    return reason, pstatus, report, rdigest


def _error_run(
    check: RequiredCheck,
    started: str,
    t0: float,
    clock: Callable[[], float],
    reason: str,
    *,
    revision: str,
    pstatus: ProviderStatus = ProviderStatus.ERROR,
) -> EvidenceRun:
    res = CheckResult(
        check.name,
        check.argv,
        CheckStatus.ERROR,
        None,
        started,
        _now(),
        round((clock() - t0) * 1000, 3),
        _EMPTY_SHA,
        "",
        reason=reason,
        source=check.source,
        revision=revision,
        provider_status=pstatus.value,
    )
    return EvidenceRun(check, res, pstatus)


def ingest_external(
    check: RequiredCheck,
    path: str | None,
    *,
    checkout_root: Path | None = None,
    expected_revisions: frozenset[str] = frozenset(),
) -> EvidenceRun:
    """Evidence produced elsewhere (e.g. a CodeQL job) and handed to the gate.

    The report must not live inside the evaluated checkout (the patch could have
    committed a clean one), and a SARIF report that names the revision it
    analysed must name the head (or the CI commit) being judged.
    """
    started = _now()
    t0 = time.monotonic()
    if path is None:
        return _error_run(
            check,
            started,
            t0,
            time.monotonic,
            f"no report supplied (pass --evidence {check.name}=PATH)",
            revision="head",
            pstatus=ProviderStatus.SKIPPED,
        )
    p = Path(path)
    try:
        if p.is_symlink() or not p.is_file():
            raise ReportError(f"{path} is not a regular file")
        if checkout_root is not None and p.resolve().is_relative_to(checkout_root.resolve()):
            raise ReportError(
                f"{path} is inside the evaluated checkout; external evidence must come from "
                "outside the tree the patch controls"
            )
        data = p.read_bytes()
        if not check.report_format:
            raise ReportError("external evidence has no format")
        report = parse_report(check.report_format, data)
        if check.require_revision and not report.revisions:
            raise ReportError(
                "require_revision: the report does not record which revision it analysed "
                "(SARIF versionControlProvenance.revisionId)"
            )
        if report.revisions and expected_revisions and not (report.revisions & expected_revisions):
            raise ReportError(
                f"report analysed revision(s) {sorted(report.revisions)}, not the evaluated "
                f"head {sorted(expected_revisions)}"
            )
    except (OSError, ReportError) as exc:
        return _error_run(check, started, t0, time.monotonic, str(exc), revision="head")
    res = CheckResult(
        check.name,
        (),
        _status_word(report.status),
        None,
        started,
        _now(),
        round((time.monotonic() - t0) * 1000, 3),
        "sha256:" + hashlib.sha256(data).hexdigest(),
        "",
        reason=report.reason,
        source="external",
        revision="head",
        provider_status=report.status.value,
        report=report.to_json(),
        report_digest="sha256:" + hashlib.sha256(data).hexdigest(),
    )
    return EvidenceRun(check, res, report.status, report)
