"""GitHub Actions workflow analysis: did the patch stop CI from testing?"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

import yaml

from aicrg.analysis.context import PatchContext
from aicrg.globmatch import match
from aicrg.model import Finding
from aicrg.rules import finding

WORKFLOW_GLOBS = (".github/workflows/*.yml", ".github/workflows/*.yaml")

TEST_CMD_RE = re.compile(
    r"(^|[\s;&|(])(python[0-9.]*\s+-m\s+)?(pytest|py\.test|tox|nox|unittest|hatch\s+(run\s+)?test|"
    r"make\s+(test|check)|npm\s+(run\s+)?test|yarn\s+test|pnpm\s+test|go\s+test|cargo\s+test|"
    r"mvn\s+\S*\s*test|gradle\w*\s+test|uv\s+run\s+pytest)\b"
)
DESELECT_RE = re.compile(
    r"(--ignore(-glob)?[=\s]|--deselect[=\s]|-k\s+['\"]?\s*not\b|-m\s+['\"]?\s*not\b|"
    r"--co\b|--collect-only\b|--lf\b|--last-failed\b|--maxfail[=\s]*0\b|--exitfirst\b.*--co)"
)
MASK_RE = re.compile(r"(\|\|\s*(true|:|exit\s+0)\b|;\s*exit\s+0\b|set\s+\+e\b|\|\|\s*echo\b)")
SCANNER_RE = re.compile(
    r"(codeql|semgrep|dependency-review|bandit|pip-audit|safety\s+check|gitleaks|trivy|"
    r"trufflehog|scorecard|snyk|osv-scanner|zizmor|aicrg|ai-code-review-gate)",
    re.I,
)
SHA_REF_RE = re.compile(r"@[0-9a-f]{40}$")
FALSE_IF = {"false", "${{ false }}", "${{false}}", "0", "${{ 0 }}"}


@dataclass(slots=True)
class Workflow:
    triggers: dict[str, Any] = field(default_factory=dict)
    test_cmds: list[str] = field(default_factory=list)
    run_lines: list[str] = field(default_factory=list)
    scanners: Counter[str] = field(default_factory=Counter)
    continue_on_error: set[str] = field(default_factory=set)
    disabled: set[str] = field(default_factory=set)
    write_scopes: set[str] = field(default_factory=set)
    uses: set[str] = field(default_factory=set)


def _norm_cmd(line: str) -> str:
    return re.sub(r"\s+", " ", line.strip())


def _run_lines(run: Any) -> list[str]:
    if not isinstance(run, str):
        return []
    out: list[str] = []
    for raw in run.replace("\\\n", " ").splitlines():
        line = _norm_cmd(raw)
        if line and not line.startswith("#"):
            out.append(line)
    return out


def _is_test_cmd(line: str) -> bool:
    if re.match(r"^(echo|printf|:)\b", line):
        return False
    return bool(TEST_CMD_RE.search(line))


def _perm_writes(perms: Any, where: str) -> set[str]:
    if perms == "write-all":
        return {f"{where}:write-all"}
    if isinstance(perms, dict):
        return {f"{where}:{k}" for k, v in perms.items() if v == "write"}
    return set()


def parse_workflow(text: str | None) -> Workflow | None:
    wf = Workflow()
    if text is None:
        return wf
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    if data is None:
        return wf
    if not isinstance(data, dict):
        return None
    # PyYAML (YAML 1.1) parses the key `on` as boolean True.
    on = data.get("on", data.get(True))
    if isinstance(on, str):
        wf.triggers = {on: None}
    elif isinstance(on, list):
        wf.triggers = {str(t): None for t in on}
    elif isinstance(on, dict):
        wf.triggers = {str(k): v for k, v in on.items()}
    wf.write_scopes |= _perm_writes(data.get("permissions"), "workflow")
    jobs = data.get("jobs") or {}
    if not isinstance(jobs, dict):
        return None
    for job_id, job in sorted(jobs.items(), key=lambda kv: str(kv[0])):
        if not isinstance(job, dict):
            continue
        jid = str(job_id)
        wf.write_scopes |= _perm_writes(job.get("permissions"), f"job {jid}")
        job_off = str(job.get("if", "")).strip().lower() in FALSE_IF
        if job_off:
            wf.disabled.add(f"job {jid}")
        if job.get("continue-on-error") is True:
            wf.continue_on_error.add(f"job {jid}")
        if isinstance(job.get("uses"), str):  # reusable workflow call
            wf.uses.add(job["uses"])
        for i, step in enumerate(job.get("steps") or []):
            if not isinstance(step, dict):
                continue
            sid = f"job {jid} step {step.get('name') or step.get('id') or i}"
            step_off = job_off or str(step.get("if", "")).strip().lower() in FALSE_IF
            if step_off and not job_off:
                wf.disabled.add(sid)
            if step.get("continue-on-error") is True:
                wf.continue_on_error.add(sid)
            uses = step.get("uses")
            if isinstance(uses, str):
                wf.uses.add(uses)
                m = SCANNER_RE.search(uses)
                if m and not step_off:
                    wf.scanners[m.group(1).lower()] += 1
            for line in _run_lines(step.get("run")):
                wf.run_lines.append(line)
                if step_off:
                    continue
                if _is_test_cmd(line):
                    wf.test_cmds.append(line)
                m = SCANNER_RE.search(line)
                if m:
                    wf.scanners[m.group(1).lower()] += 1
    return wf


def analyze_workflows(ctx: PatchContext) -> list[Finding]:
    out: list[Finding] = []
    c = ctx.contract
    for fc in ctx.patch.files:
        if not any(match(p, g) for p in fc.paths for g in WORKFLOW_GLOBS):
            continue
        before = parse_workflow(ctx.base_text(fc) if fc.old_path else None)
        after = parse_workflow(ctx.head_text(fc) if fc.new_path else None)
        if before is None or after is None:
            out.append(
                finding(
                    "ci_config_unparseable", c, "workflow YAML could not be parsed", file=fc.path
                )
            )
            continue
        f = fc.path
        if len(after.test_cmds) < len(before.test_cmds):
            gone = [t for t in before.test_cmds if t not in after.test_cmds]
            out.append(
                finding(
                    "ci_test_step_removed",
                    c,
                    f"workflow runs {len(before.test_cmds)} -> {len(after.test_cmds)} "
                    "test command(s)" + (" (workflow deleted)" if fc.status == "D" else ""),
                    file=f,
                    before="; ".join(gone[:3]),
                )
            )
        for cmd in after.test_cmds:
            if cmd in before.test_cmds:
                continue
            if DESELECT_RE.search(cmd):
                out.append(
                    finding(
                        "ci_tests_deselected",
                        c,
                        "test command now deselects tests",
                        file=f,
                        after=cmd,
                    )
                )
        old_lines = Counter(before.run_lines)
        for line in after.run_lines:
            if old_lines[line] > 0:
                old_lines[line] -= 1
                continue
            if MASK_RE.search(line):
                out.append(
                    finding("ci_failure_masked", c, "command failure is masked", file=f, after=line)
                )
        for where in sorted(after.continue_on_error - before.continue_on_error):
            out.append(
                finding("ci_failure_masked", c, f"continue-on-error added to {where}", file=f)
            )
        for where in sorted(after.disabled - before.disabled):
            out.append(finding("ci_job_disabled", c, f"{where} disabled by constant `if`", file=f))
        for trig in ("pull_request", "push", "merge_group"):
            if trig in before.triggers and trig not in after.triggers and fc.status != "D":
                out.append(
                    finding("ci_trigger_removed", c, f"workflow no longer runs on {trig}", file=f)
                )
        for trig in ("pull_request", "push"):
            cfg_b = before.triggers.get(trig) or {}
            cfg_a = after.triggers.get(trig) or {}
            if isinstance(cfg_a, dict) and isinstance(cfg_b, dict):
                for key in ("paths-ignore", "paths"):
                    if cfg_a.get(key) and cfg_a.get(key) != cfg_b.get(key):
                        out.append(
                            finding(
                                "ci_paths_ignore_added",
                                c,
                                f"{trig}.{key} filter changed: {cfg_a.get(key)}",
                                file=f,
                            )
                        )
        for scanner, n in sorted(before.scanners.items()):
            if after.scanners.get(scanner, 0) < n:
                out.append(
                    finding(
                        "security_scanner_removed",
                        c,
                        f"security/gate step `{scanner}` removed or disabled",
                        file=f,
                    )
                )
        for trig in ("pull_request_target", "workflow_run"):
            if trig in after.triggers and trig not in before.triggers:
                out.append(
                    finding(
                        "dangerous_trigger_added",
                        c,
                        f"`{trig}` runs with base-repo secrets/permissions; executing "
                        "PR code under it exposes them",
                        file=f,
                    )
                )
        for scope in sorted(after.write_scopes - before.write_scopes):
            out.append(
                finding(
                    "workflow_permissions_widened", c, f"write permission added: {scope}", file=f
                )
            )
        for uses in sorted(after.uses - before.uses):
            if uses.startswith(("./", "docker://")) or SHA_REF_RE.search(uses):
                continue
            out.append(
                finding(
                    "unpinned_action_added", c, f"`{uses}` is not pinned to a commit SHA", file=f
                )
            )
    return out
