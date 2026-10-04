"""Gate orchestration: patch -> provenance -> contract -> risk -> evidence -> decision -> receipt.

Invariant: any stage that cannot complete records a ``GateError``; any
``GateError`` without a blocking finding yields ERROR. There is no code path
from an exception to PASS.
"""

from __future__ import annotations

import platform
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar

from aicrg import GATE_NAME, __version__
from aicrg.analysis.context import PatchContext
from aicrg.dependencies.delta import DependencyReport, analyze_dependencies
from aicrg.evidence.commands import filtered_env, run_check
from aicrg.evidence.workspace import head_worktree
from aicrg.git.diff import FileChange, Patch, extract_patch
from aicrg.git.repo import Repo
from aicrg.globmatch import match_any
from aicrg.llm.reviewer import ReviewerResult, run_reviewer
from aicrg.model import CheckResult, CheckStatus, Decision, Finding, GateError, Severity
from aicrg.policy.contract import ReviewContract
from aicrg.policy.loader import LoadedPolicy, load_policy
from aicrg.receipt.receipt import SCHEMA, seal
from aicrg.risk.surfaces import RiskAssessment, RiskLevel, assess
from aicrg.rules import finding
from aicrg.security.regressions import analyze_security
from aicrg.security.secrets import analyze_secrets
from aicrg.testsafety.ci import analyze_workflows
from aicrg.testsafety.config import analyze_config, analyze_suppressions
from aicrg.testsafety.integrity import TestIntegrityReport, analyze_test_integrity

T = TypeVar("T")

SECTIONS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Change contract", ("contract",)),
    ("Required checks", ("evidence",)),
    ("Test integrity", ("test_integrity",)),
    ("CI integrity", ("ci_integrity",)),
    ("Security regressions", ("security",)),
    ("Dependency policy", ("dependencies",)),
    ("Analysis coverage", ("analysis",)),
    ("Reviewer model (advisory)", ("llm_review",)),
)
STAGE_SECTION = {
    "contract": "Change contract",
    "evidence": "Required checks",
    "test_integrity": "Test integrity",
    "ci_integrity": "CI integrity",
    "config": "Test integrity",
    "suppressions": "Test integrity",
    "security": "Security regressions",
    "secrets": "Security regressions",
    "dependencies": "Dependency policy",
    "llm_review": "Reviewer model (advisory)",
}


@dataclass(slots=True)
class GateOptions:
    base: str
    head: str = "HEAD"
    policy: str | None = None
    policy_from: str = "base"
    run_checks: bool = True
    receipt_dir: Path | None = None


@dataclass(slots=True)
class GateResult:
    decision: Decision
    receipt: dict[str, Any]
    findings: list[Finding] = field(default_factory=list)
    errors: list[GateError] = field(default_factory=list)
    checks: list[CheckResult] = field(default_factory=list)
    sections: dict[str, str] = field(default_factory=dict)
    receipt_path: Path | None = None


def decide(findings: list[Finding], errors: list[GateError]) -> Decision:
    if any(f.severity is Severity.BLOCK for f in findings):
        return Decision.FAIL
    if errors:
        return Decision.ERROR
    if any(f.severity is Severity.REVIEW for f in findings):
        return Decision.REVIEW_REQUIRED
    return Decision.PASS


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class _Run:
    def __init__(self, opts: GateOptions, cwd: Path) -> None:
        self.opts = opts
        self.cwd = cwd
        self.findings: list[Finding] = []
        self.errors: list[GateError] = []
        self.checks: list[CheckResult] = []
        self.timings: dict[str, float] = {}
        self.subject: dict[str, Any] = {"base_ref": opts.base, "head_ref": opts.head}
        self.policy: LoadedPolicy | None = None
        self.risk: RiskAssessment | None = None
        self.ti: TestIntegrityReport | None = None
        self.deps: DependencyReport | None = None
        self.reviewer: ReviewerResult | None = None
        self.env_info: dict[str, Any] = {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "machine": platform.machine(),
        }
        self.errored_stages: set[str] = set()

    def stage(self, name: str, fn: Callable[[], T]) -> T | None:
        t0 = time.perf_counter()
        try:
            return fn()
        except Exception as exc:  # any analyser failure is a gate failure, never a pass
            self.errors.append(GateError(name, f"{type(exc).__name__}: {exc}"))
            self.errored_stages.add(name)
            return None
        finally:
            self.timings[name] = round((time.perf_counter() - t0) * 1000, 3)


def run_gate(opts: GateOptions, cwd: Path | None = None) -> GateResult:
    run = _Run(opts, cwd or Path.cwd())
    started = _now()
    t_total = time.perf_counter()

    repo = run.stage("provenance", lambda: Repo.discover(run.cwd))
    patch: Patch | None = None
    contract = ReviewContract()
    if repo is not None:
        prov = run.stage("provenance", lambda: _provenance(repo, opts, run))
        if prov is not None:
            base_sha, merge_base, head_sha = prov
            pol = run.stage(
                "policy", lambda: load_policy(repo, base_sha, opts.policy, opts.policy_from)
            )
            if pol is not None:
                run.policy = pol
                contract = pol.contract
            patch = run.stage("patch", lambda: extract_patch(repo, merge_base, head_sha))
    if repo is not None and patch is not None:
        run.subject["patch_digest"] = patch.digest
        run.subject["patch_bytes"] = patch.size_bytes
        run.subject["files"] = [f.to_json() for f in patch.files]
        if run.policy is not None:
            _analyse(run, repo, patch, contract)
        else:
            # Without a valid contract we still describe the patch, but decide nothing.
            run.risk = run.stage("risk", lambda: assess(PatchContext(repo, patch, contract), None))

    decision = decide(run.findings, run.errors)
    run.timings["total"] = round((time.perf_counter() - t_total) * 1000, 3)
    findings = sorted(run.findings, key=Finding.sort_key)
    sections = _sections(run, findings)
    receipt = _receipt(run, decision, findings, sections, started)
    return GateResult(decision, receipt, findings, run.errors, run.checks, sections)


def _provenance(repo: Repo, opts: GateOptions, run: _Run) -> tuple[str, str, str]:
    base_sha = repo.resolve_commit(opts.base)
    head_sha = repo.resolve_commit(opts.head)
    merge_base = repo.merge_base(base_sha, head_sha)
    run.subject.update(
        {
            "repository": repo.identity(),
            "base": base_sha,
            "merge_base": merge_base,
            "head": head_sha,
            "head_tree": repo.tree_of(head_sha),
            "working_tree_dirty": repo.is_dirty(),
        }
    )
    run.env_info["git"] = repo.git_version()
    return base_sha, merge_base, head_sha


NEVER_EXCLUDED = (".github/workflows/*.yml", ".github/workflows/*.yaml")


def _content_patch(patch: Patch, contract: ReviewContract, policy_path: str | None) -> Patch:
    """The patch as seen by content analysers (``exclude_from_analysis`` removed)."""
    if not contract.exclude_from_analysis:
        return patch

    def excluded(fc: FileChange) -> bool:
        for p in fc.paths:
            if p == policy_path or match_any(p, NEVER_EXCLUDED):
                return False
        return all(match_any(p, contract.exclude_from_analysis) for p in fc.paths)

    kept = [fc for fc in patch.files if not excluded(fc)]
    return Patch(patch.base, patch.head, kept, patch.digest, patch.size_bytes)


def _analyse(run: _Run, repo: Repo, patch: Patch, contract: ReviewContract) -> None:
    full = PatchContext(repo, patch, contract)
    policy_path = run.policy.repo_path if run.policy else None
    run.risk = run.stage("risk", lambda: assess(full, policy_path))
    run.stage("contract", lambda: run.findings.extend(_contract_findings(full, run)))
    content = _content_patch(patch, contract, policy_path)
    run.subject["files_excluded_from_analysis"] = len(patch.files) - len(content.files)
    ctx = PatchContext(repo, content, contract)
    ti = run.stage("test_integrity", lambda: analyze_test_integrity(ctx))
    if ti is not None:
        run.ti = ti
        run.findings.extend(ti.findings)
    for name, fn in (
        ("config", analyze_config),
        ("suppressions", analyze_suppressions),
        ("ci_integrity", analyze_workflows),
        ("security", analyze_security),
        ("secrets", analyze_secrets),
    ):
        res = run.stage(name, lambda fn=fn: fn(ctx))  # type: ignore[misc]
        if res is not None:
            run.findings.extend(res)
    deps = run.stage("dependencies", lambda: analyze_dependencies(ctx))
    if deps is not None:
        run.deps = deps
        run.findings.extend(deps.findings)
    run.stage("evidence", lambda: _evidence(run, repo, patch, contract))
    reviewer = run.stage("llm_review", lambda: run_reviewer(contract.llm_reviewer, patch, contract))
    if reviewer is not None:
        run.reviewer = reviewer
        run.findings.extend(reviewer.findings)
        if reviewer.status == "error" and contract.llm_reviewer and contract.llm_reviewer.required:
            run.errors.append(GateError("llm_review", reviewer.error or "reviewer failed"))
            run.errored_stages.add("llm_review")


def _contract_findings(ctx: PatchContext, run: _Run) -> list[Finding]:
    c = ctx.contract
    out: list[Finding] = []
    policy_path = run.policy.repo_path if run.policy else None
    for fc in ctx.patch.files:
        for p in fc.paths:
            if c.allowed_paths and match_any(p, c.allowed_paths) is None:
                out.append(
                    finding(
                        "path_outside_contract",
                        c,
                        f"{fc.status_word()} file is outside allowed_paths",
                        file=p,
                    )
                )
            pat = match_any(p, c.protected_paths)
            if pat:
                out.append(
                    finding(
                        "protected_path_modified",
                        c,
                        f"{fc.status_word()} protected path ({pat})",
                        file=p,
                    )
                )
            if policy_path is not None and p == policy_path:
                out.append(
                    finding(
                        "policy_modified",
                        c,
                        "patch edits the review contract; this run used the "
                        f"{run.policy.source if run.policy else ''} version",
                        file=p,
                    )
                )
    if run.risk is not None:
        for surface in c.review_required_surfaces:
            files = sorted({h.file for h in run.risk.hits if h.surface == surface})
            if files:
                out.append(
                    finding(
                        "review_required_surface",
                        c,
                        f"contract requires human review for `{surface}` changes "
                        f"({', '.join(files[:5])})",
                    )
                )
    return out


def _evidence(run: _Run, repo: Repo, patch: Patch, contract: ReviewContract) -> None:
    c = contract
    if not c.required_checks:
        if run.risk is not None and run.risk.level >= RiskLevel.HIGH:
            run.findings.append(
                finding(
                    "insufficient_evidence",
                    c,
                    f"{run.risk.level.name} risk patch ({', '.join(run.risk.surfaces)}) but the "
                    "contract defines no required checks; nothing was executed",
                )
            )
        return
    if not run.opts.run_checks:
        run.errors.append(
            GateError(
                "evidence",
                "required checks were not executed (--no-run); "
                "the gate cannot vouch for this patch",
            )
        )
        run.errored_stages.add("evidence")
        return
    env, dropped = filtered_env(c.env_passthrough)
    run.env_info["env_vars_withheld_from_checks"] = len(dropped)
    with head_worktree(repo, patch.head) as wt:
        for check in c.required_checks:
            res = run_check(check, wt, env)
            run.checks.append(res)
            if res.status is CheckStatus.FAIL:
                run.findings.append(
                    finding(
                        "required_check_failed",
                        c,
                        f"required check `{check.name}` failed: {res.reason}",
                        after=res.output_tail[-300:] or None,
                    )
                )
            elif res.status is CheckStatus.ERROR:
                run.errors.append(
                    GateError(
                        "evidence",
                        f"required check `{check.name}` could not complete: {res.reason}",
                    )
                )
                run.errored_stages.add("evidence")


def _sections(run: _Run, findings: list[Finding]) -> dict[str, str]:
    out: dict[str, str] = {}
    for title, categories in SECTIONS:
        sev = {f.severity for f in findings if f.category in categories}
        if Severity.BLOCK in sev:
            status = "FAIL"
        elif any(STAGE_SECTION.get(s) == title for s in run.errored_stages):
            status = "ERROR"
        elif Severity.REVIEW in sev:
            status = "REVIEW"
        else:
            status = "PASS"
        out[title] = status
    if run.policy is None:
        return {t: "ERROR" for t in out}
    c = run.policy.contract
    if not c.required_checks and out["Required checks"] == "PASS":
        out["Required checks"] = "NONE"
    if c.llm_reviewer is None:
        out["Reviewer model (advisory)"] = "OFF"
    return out


def _receipt(
    run: _Run, decision: Decision, findings: list[Finding], sections: dict[str, str], started: str
) -> dict[str, Any]:
    blocking = [f for f in findings if f.severity is Severity.BLOCK]
    review = [f for f in findings if f.severity is Severity.REVIEW]
    reasons = (
        [f"{f.code}: {f.file + ': ' if f.file else ''}{f.message}" for f in blocking]
        + [f"gate error ({e.stage}): {e.message}" for e in run.errors]
        + [f"{f.code}: {f.file + ': ' if f.file else ''}{f.message}" for f in review]
    )
    ti_result = sections.get("Test integrity", "PASS")
    receipt: dict[str, Any] = {
        "schema": SCHEMA,
        "gate": {"name": GATE_NAME, "version": __version__},
        "decision": decision.value,
        "reasons": reasons[:50],
        "subject": run.subject,
        "policy": run.policy.to_json() if run.policy else None,
        "risk": run.risk.to_json() if run.risk else None,
        "sections": sections,
        "checks": [c.to_json() for c in run.checks],
        "findings": [f.to_json() for f in findings],
        "summary": {
            "blocking": len(blocking),
            "review": len(review),
            "advisory": sum(1 for f in findings if f.severity is Severity.ADVISORY),
            "deterministic_failures": sorted(
                {f.code for f in blocking if f.kind.value == "deterministic"}
            ),
            "heuristic_failures": sorted({f.code for f in blocking if f.kind.value == "heuristic"}),
            "errors": len(run.errors),
        },
        "test_integrity": {"result": ti_result, **(run.ti.to_json() if run.ti else {})},
        "dependencies": run.deps.to_json() if run.deps else [],
        "llm_review": run.reviewer.to_json() if run.reviewer else {"status": "not_run"},
        "errors": [e.to_json() for e in run.errors],
        "environment": {**run.env_info, "aicrg": __version__},
        "timestamps": {"started_at": started, "finished_at": _now()},
        "timings_ms": run.timings,
    }
    return seal(receipt)
