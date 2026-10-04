"""``aicrg doctor``: can a pull request disable its own gate?

A gate is only as strong as its enforcement. If the workflow that runs AICRG
lives in the tree the pull request modifies, the pull request can delete the
step, mask its exit code, or loosen the policy it is judged by. ``doctor``
inspects the deployment, statically (repository files) and optionally through
the GitHub API (``--github``), and reports each hazard:

PASS     the property holds.
WARN     a weakness an operator should consciously accept.
FAIL     the gate can be bypassed or the configuration is unsafe.
UNKNOWN  the property could not be checked (e.g. the API token lacks
         permission). UNKNOWN is never reported as PASS.

Exit status: 0 when nothing FAILs or is UNKNOWN (``--strict`` also fails on
WARN), 1 on FAIL, 4 when only UNKNOWN prevents a verdict.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from aicrg.globmatch import match_any
from aicrg.policy.contract import DEFAULT_POLICY_FILES, PolicyError, ReviewContract, parse_contract

_SHA_PIN = re.compile(r"@[0-9a-f]{40}$")
_HEAD_REF = re.compile(
    r"github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref|"
    r"github\.event\.workflow_run\.head_(sha|branch)|refs/pull/"
)
_MASK = re.compile(r"\|\|\s*(true|:|exit\s+0)\b|;\s*exit\s+0\b|set\s+\+e")
# The gate command at the start of a shell command (not inside an echo or a string).
_GATE_RUN = re.compile(
    r"(?:^|[;&|(]\s*|\bthen\s+|\bdo\s+)(?:\S*/)?(?:aicrg|python3?\s+-m\s+aicrg)\s+check\b",
    re.M,
)
_GATE_USES = re.compile(r"ai-code-review-gate(@|$)", re.I)


@dataclass(slots=True)
class Check:
    id: str
    status: str  # PASS | WARN | FAIL | UNKNOWN
    message: str
    file: str | None = None

    def to_json(self) -> dict[str, Any]:
        d: dict[str, Any] = {"id": self.id, "status": self.status, "message": self.message}
        if self.file:
            d["file"] = self.file
        return d


@dataclass(slots=True)
class Report:
    checks: list[Check] = field(default_factory=list)

    def add(self, id_: str, status: str, message: str, file: str | None = None) -> None:
        self.checks.append(Check(id_, status, message, file))

    def verdict(self, strict: bool = False) -> str:
        sts = {c.status for c in self.checks}
        if "FAIL" in sts or (strict and "WARN" in sts):
            return "FAIL"
        if "UNKNOWN" in sts:
            return "UNKNOWN"
        return "PASS"

    def exit_code(self, strict: bool = False) -> int:
        return {"PASS": 0, "FAIL": 1, "UNKNOWN": 4}[self.verdict(strict)]


# --------------------------------------------------------------------------- workflows


@dataclass(slots=True)
class Workflow:
    path: str
    doc: dict[Any, Any]

    @property
    def triggers(self) -> set[str]:
        on = self.doc.get("on", self.doc.get(True))  # YAML 1.1 parses `on` as True
        if isinstance(on, str):
            return {on}
        if isinstance(on, list):
            return {str(x) for x in on}
        if isinstance(on, dict):
            return {str(k) for k in on}
        return set()

    def jobs(self) -> dict[str, dict[str, Any]]:
        jobs = self.doc.get("jobs")
        return (
            {k: v for k, v in jobs.items() if isinstance(v, dict)} if isinstance(jobs, dict) else {}
        )


def _maybe_true(value: Any) -> bool:
    """continue-on-error that is not provably false (literals or `${{ ... }}` expressions)."""
    if value is None or value is False:
        return False
    text = re.sub(r"\s+", "", str(value).lower())
    return text not in ("false", "${{false}}", "0", "${{0}}")


def _gate_line_hazards(run: str, shell: str) -> list[str]:
    """Shell constructs on the gate's own command line that lose its exit status."""
    out: list[str] = []
    for line in run.splitlines():
        if not _GATE_RUN.search(line):
            continue
        rest = line[_GATE_RUN.search(line).end() :]  # type: ignore[union-attr]
        if re.search(r"\|\|", rest):
            out.append("gate command followed by `||` (failure handled/ignored)")
        elif re.search(r"(?<!\|)\|(?!\|)", rest) and not _pipefail(run, shell):
            out.append("gate output piped without `set -o pipefail` (exit status lost)")
    return out


def _pipefail(run: str, shell: str) -> bool:
    # `shell: bash` on GitHub runs `bash --noprofile --norc -eo pipefail {0}`; the default
    # (no shell key) is `bash -e {0}`, which does NOT set pipefail.
    return "pipefail" in run or "pipefail" in shell or shell.strip() == "bash"


def _never(cond: Any) -> bool:
    """An `if:` that can never be true (YAML may hand us the boolean False)."""
    text = re.sub(r"\s+", "", str(cond).lower())
    return cond is False or text in ("false", "${{false}}", "0", "${{0}}")


def _steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    steps = job.get("steps")
    return [s for s in steps if isinstance(s, dict)] if isinstance(steps, list) else []


def _is_gate_step(step: dict[str, Any], local_action_is_gate: bool) -> bool:
    uses = str(step.get("uses", ""))
    run = str(step.get("run", ""))
    if _GATE_RUN.search(run) or _GATE_USES.search(uses.split("@", maxsplit=1)[0] + "@"):
        return True
    return uses.strip() in ("./", ".") and local_action_is_gate


def load_workflows(root: Path) -> tuple[list[Workflow], list[str]]:
    out: list[Workflow] = []
    bad: list[str] = []
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return out, bad
    for p in sorted(wf_dir.iterdir()):
        if p.suffix not in (".yml", ".yaml") or not p.is_file():
            continue
        rel = p.relative_to(root).as_posix()
        try:
            doc = yaml.safe_load(p.read_text(encoding="utf-8"))
        except (yaml.YAMLError, UnicodeDecodeError):
            bad.append(rel)
            continue
        if isinstance(doc, dict):
            out.append(Workflow(rel, doc))
        else:
            bad.append(rel)
    return out, bad


def _local_action_is_gate(root: Path) -> bool:
    for name in ("action.yml", "action.yaml"):
        p = root / name
        if p.is_file():
            text = p.read_text(encoding="utf-8", errors="replace")
            return "aicrg" in text and "check" in text
    return False


def _contract(root: Path) -> tuple[ReviewContract | None, str | None, str | None]:
    for name in DEFAULT_POLICY_FILES:
        p = root / name
        if p.is_file():
            try:
                return parse_contract(p.read_text(encoding="utf-8")), name, None
            except (PolicyError, UnicodeDecodeError) as exc:
                return None, name, str(exc)
    return None, None, None


def static_checks(root: Path, report: Report | None = None) -> Report:
    rep = report or Report()
    workflows, unparseable = load_workflows(root)
    for rel in unparseable:
        rep.add("workflow-parse", "UNKNOWN", "workflow could not be parsed", rel)
    local_gate = _local_action_is_gate(root)
    gate_jobs: list[tuple[Workflow, str, dict[str, Any]]] = []

    for wf in workflows:
        trig = wf.triggers
        perms = wf.doc.get("permissions")
        # ---- dangerous triggers
        for t in ("pull_request_target", "workflow_run"):
            if t not in trig:
                continue
            checks_out_head = any(
                _HEAD_REF.search(json.dumps(s.get("with", {})))
                for job in wf.jobs().values()
                for s in _steps(job)
                if str(s.get("uses", "")).startswith("actions/checkout")
            )
            if checks_out_head:
                rep.add(
                    "dangerous-trigger",
                    "FAIL",
                    f"`{t}` runs with repository secrets/write token and checks out "
                    "untrusted PR code (pwn-request pattern)",
                    wf.path,
                )
            else:
                rep.add(
                    "dangerous-trigger",
                    "WARN",
                    f"`{t}` trigger: never check out or execute PR code in this workflow",
                    wf.path,
                )
        # ---- token permissions
        if perms is None:
            rep.add(
                "token-permissions",
                "WARN",
                "no top-level `permissions:`; the default GITHUB_TOKEN may have write access",
                wf.path,
            )
        elif perms == "write-all" or (
            isinstance(perms, dict) and any(v == "write" for v in perms.values())
        ):
            rep.add(
                "token-permissions",
                "FAIL" if trig & {"pull_request", "pull_request_target"} else "WARN",
                f"workflow-wide write permissions: {perms}",
                wf.path,
            )
        else:
            rep.add("token-permissions", "PASS", "workflow token is read-only by default", wf.path)
        # ---- action pinning
        unpinned = sorted(
            {
                str(s["uses"])
                for job in wf.jobs().values()
                for s in _steps(job)
                if "uses" in s
                and not str(s["uses"]).startswith(("./", "docker://"))
                and not _SHA_PIN.search(str(s["uses"]))
            }
        )
        if unpinned:
            rep.add(
                "action-pinning",
                "WARN",
                f"actions not pinned to a commit SHA: {', '.join(unpinned[:5])}",
                wf.path,
            )
        # ---- gate jobs
        for name, job in wf.jobs().items():
            if any(_is_gate_step(s, local_gate) for s in _steps(job)):
                gate_jobs.append((wf, name, job))

    if not gate_jobs:
        rep.add("gate-present", "FAIL", "no workflow runs `aicrg check` or the AICRG action")
    for wf, name, job in gate_jobs:
        where = f"{wf.path}#{name}"
        rep.add("gate-present", "PASS", f"gate runs in job `{name}`", wf.path)
        masked: list[str] = []
        if _maybe_true(job.get("continue-on-error")):
            masked.append("job continue-on-error")
        if _never(job.get("if")):
            masked.append("job `if: false`")
        for s in _steps(job):
            if _is_gate_step(s, local_gate):
                if _maybe_true(s.get("continue-on-error")):
                    masked.append("step continue-on-error")
                run_text = str(s.get("run", ""))
                if _MASK.search(run_text):
                    masked.append("exit status masked in `run`")
                masked += _gate_line_hazards(run_text, str(s.get("shell", "")))
                if _never(s.get("if")):
                    masked.append("step `if: false`")
                run = str(s.get("run", ""))
                if "--policy-from file" in run or "--policy-from=file" in run:
                    masked.append("policy read from the working tree (--policy-from file)")
        if masked:
            rep.add(
                "gate-not-masked", "FAIL", f"gate result can be ignored: {', '.join(masked)}", where
            )
        else:
            rep.add("gate-not-masked", "PASS", "gate exit status is enforced", where)
        trig = wf.triggers
        if "pull_request_target" in trig:
            rep.add(
                "gate-trigger",
                "FAIL",
                "gate runs under pull_request_target: candidate code would run with secrets",
                where,
            )
        secrets = sorted(set(re.findall(r"secrets\.([A-Za-z0-9_]+)", json.dumps(job))))
        secrets = [x for x in secrets if x != "GITHUB_TOKEN"]
        if secrets:
            rep.add(
                "gate-secrets",
                "FAIL",
                f"gate job exposes secrets {secrets} to a job that executes candidate code",
                where,
            )
        for s in _steps(job):
            if str(s.get("uses", "")).startswith("actions/checkout"):
                w = s.get("with") or {}
                if w.get("persist-credentials") not in (False, "false"):
                    rep.add(
                        "checkout-credentials",
                        "WARN",
                        "checkout persists the token in .git/config, readable by candidate code",
                        where,
                    )
        jperm = job.get("permissions")
        if jperm == "write-all" or (
            isinstance(jperm, dict) and any(v == "write" for v in jperm.values())
        ):
            rep.add("gate-permissions", "FAIL", f"gate job has write permissions {jperm}", where)

    # ---- contract
    contract, policy_file, err = _contract(root)
    if err:
        rep.add("policy", "FAIL", f"review contract is invalid: {err}", policy_file)
    elif contract is None:
        rep.add("policy", "WARN", "no review contract; the strict built-in default applies")
    else:
        rep.add("policy", "PASS", "review contract parses", policy_file)
        assert policy_file is not None  # noqa: S101 - set with contract
        if match_any(policy_file, contract.protected_paths) is None:
            rep.add(
                "policy-protected",
                "WARN",
                f"{policy_file} is not in protected_paths; policy edits only need review",
                policy_file,
            )
        else:
            rep.add("policy-protected", "PASS", "policy file is a protected path", policy_file)
        wf_protected = match_any(".github/workflows/gate.yml", contract.protected_paths)
        if wf_protected is None and "ci" not in contract.review_required_surfaces:
            rep.add(
                "acceptance-config",
                "WARN",
                "workflow changes are neither protected nor routed to review "
                "(review_required_surfaces: [ci]); a PR can edit the gate workflow",
                policy_file,
            )
        else:
            rep.add("acceptance-config", "PASS", "workflow changes need human review", policy_file)
        if contract.executor == "local":
            rep.add(
                "executor",
                "WARN",
                "evidence runs with the local executor (no sandbox); acceptable only on "
                "ephemeral runners without secrets",
                policy_file,
            )
        else:
            rep.add("executor", "PASS", "evidence runs in a container", policy_file)
            if contract.container and "@sha256:" not in contract.container.image:
                rep.add(
                    "executor-image", "WARN", "container image is not digest-pinned", policy_file
                )
        if not contract.required_checks and not contract.trusted_evidence:
            rep.add("evidence", "WARN", "contract executes no evidence", policy_file)
        if not contract.attestation.required:
            rep.add(
                "attestation",
                "WARN",
                "receipts are not required to be attested; integrity only, no authenticity",
                policy_file,
            )
    return rep


# --------------------------------------------------------------------------- GitHub API

Api = Callable[[str], tuple[int, Any]]


def default_api() -> Api:
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:

        def get(path: str) -> tuple[int, Any]:
            req = urllib.request.Request(
                f"https://api.github.com/{path.lstrip('/')}",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - fixed https host  # nosec B310
                    return resp.status, json.loads(resp.read().decode())
            except urllib.error.HTTPError as exc:
                return exc.code, None
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
                return 0, None

        return get
    if shutil.which("gh"):

        def gh_get(path: str) -> tuple[int, Any]:
            proc = subprocess.run(
                ["gh", "api", path.lstrip("/")], capture_output=True, timeout=60, check=False
            )
            if proc.returncode == 0:
                try:
                    return 200, json.loads(proc.stdout.decode())
                except json.JSONDecodeError:
                    return 0, None
            m = re.search(r"HTTP (\d{3})", proc.stderr.decode("utf-8", "replace"))
            return (int(m.group(1)) if m else 0), None

        return gh_get

    def none(path: str) -> tuple[int, Any]:
        return 0, None

    return none


def github_checks(
    repo: str, branch: str, check_names: list[str], api: Api, report: Report | None = None
) -> Report:
    rep = report or Report()
    status, rules = api(f"repos/{repo}/rules/branches/{branch}")
    if status != 200 or not isinstance(rules, list):
        rep.add(
            "github-rules",
            "UNKNOWN",
            f"cannot read branch rules for {repo}@{branch} (HTTP {status or 'error'}); "
            "enforcement is unverified",
        )
        rules = None
    required: list[str] = []
    strict = False
    workflows: list[dict[str, Any]] = []
    if rules is not None:
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            params = rule.get("parameters") or {}
            if rule.get("type") == "required_status_checks":
                required += [
                    str(c.get("context")) for c in params.get("required_status_checks", [])
                ]
                strict = strict or bool(params.get("strict_required_status_checks_policy"))
            elif rule.get("type") == "workflows":
                workflows += list(params.get("workflows", []))
    pstatus, prot = api(f"repos/{repo}/branches/{branch}/protection")
    if pstatus == 200 and isinstance(prot, dict):
        rsc = prot.get("required_status_checks") or {}
        required += [str(c) for c in rsc.get("contexts", [])]
        required += [str(c.get("context")) for c in rsc.get("checks", []) if isinstance(c, dict)]
        strict = strict or bool(rsc.get("strict"))
        if not (prot.get("enforce_admins") or {}).get("enabled"):
            rep.add("github-admin-bypass", "WARN", "branch protection does not apply to admins")
    elif pstatus not in (404,):
        rep.add(
            "github-protection",
            "UNKNOWN",
            f"cannot read classic branch protection (HTTP {pstatus or 'error'}; needs admin)",
        )
    if rules is None and pstatus != 200:
        return rep
    wanted = [n for n in check_names if n]
    hit = sorted({r for r in required if any(w == r or r.endswith(f" / {w}") for w in wanted)})
    if hit:
        rep.add("github-required-check", "PASS", f"gate is a required status check: {hit}")
    else:
        rep.add(
            "github-required-check",
            "FAIL",
            f"none of {wanted} is a required status check on {branch} "
            f"(required: {sorted(set(required)) or 'none'}); the gate is advisory only",
        )
    rep.add(
        "github-up-to-date",
        "PASS" if strict else "WARN",
        "branches must be up to date before merging"
        if strict
        else "branches need not be up to date; merge with verify-receipt --base or enable strict",
    )
    if workflows:
        rep.add(
            "github-required-workflow",
            "PASS",
            f"ruleset requires workflow(s) from a protected ref: "
            f"{[w.get('path') for w in workflows][:3]}",
        )
    else:
        rep.add(
            "github-required-workflow",
            "WARN",
            "the gate runs from a workflow file the pull request can edit; a ruleset "
            "'require workflows to pass' (or an external runner) removes that path",
        )
    return rep


def gate_job_names(root: Path) -> list[str]:
    workflows, _ = load_workflows(root)
    local_gate = _local_action_is_gate(root)
    names: list[str] = []
    for wf in workflows:
        for name, job in wf.jobs().items():
            if any(_is_gate_step(s, local_gate) for s in _steps(job)):
                names.append(str(job.get("name") or name))
    return names
