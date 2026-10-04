"""Collect and judge all executed / supplied evidence for one gate run.

Order of work:

1. Choose the executor. The base contract's ``execution.executor`` is a floor:
   an operator may upgrade ``local`` to ``container`` but never downgrade, and
   an unavailable container runtime is ERROR, never a silent local fallback.
2. ``required_checks`` (source ``head``) run in a clean checkout of the head.
3. Checks marked ``differential`` also run in a clean checkout of the merge-base.
4. ``trusted_evidence`` runs in a separate clean head checkout after the trusted
   content (base files or a digest-verified bundle) has been overlaid.
   Differential trusted evidence also runs on the merge-base with the same overlay.
5. ``external_evidence`` reports supplied by the operator are ingested.

Judging is fail-closed: a required item that is SKIPPED, ERROR or TIMEOUT adds
a ``GateError`` (decision ERROR); failures block unless a differential run
proves them pre-existing and the contract says how to treat that.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aicrg.analysis.context import is_python, is_test_path
from aicrg.evidence.commands import EvidenceRun, filtered_env, ingest_external, run_check
from aicrg.evidence.differential import DiffClass, classify, severity_for
from aicrg.evidence.executor import (
    ContainerExecutor,
    ContainerSettings,
    Executor,
    ExecutorError,
    LocalExecutor,
)
from aicrg.evidence.providers import UNAVAILABLE, ProviderStatus, changed_line_coverage
from aicrg.evidence.trusted import (
    Overlay,
    TrustedEvidenceError,
    base_entries,
    load_bundle,
    overlay_base,
    overlay_bundle,
)
from aicrg.evidence.workspace import checkout
from aicrg.git.diff import Patch
from aicrg.git.repo import Repo
from aicrg.globmatch import match_any
from aicrg.model import Finding, GateError, Severity
from aicrg.policy.contract import RequiredCheck, ReviewContract, TrustedEvidence
from aicrg.rules import finding


@dataclass(slots=True)
class CollectOptions:
    executor: str | None = None  # operator override: "local" | "container"
    container_image: str | None = None  # image when the operator upgrades to container
    bundles: dict[str, str] = field(default_factory=dict)  # trusted evidence name -> path
    external: dict[str, str] = field(default_factory=dict)  # external evidence name -> path


@dataclass(slots=True)
class EvidenceOutcome:
    runs: list[EvidenceRun] = field(default_factory=list)
    overlays: list[Overlay] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[GateError] = field(default_factory=list)
    execution: dict[str, Any] = field(default_factory=dict)
    summary: list[dict[str, Any]] = field(default_factory=list)
    env_withheld: int = 0


def build_executor(contract: ReviewContract, opts: CollectOptions) -> Executor:
    want = contract.executor
    if opts.executor is not None:
        if opts.executor not in ("local", "container"):
            raise ExecutorError(f"unknown executor {opts.executor!r}")
        if want == "container" and opts.executor == "local":
            raise ExecutorError(
                "the base contract requires container execution; refusing to run "
                "evidence with the local (unisolated) executor"
            )
        want = opts.executor
    if want == "local":
        return LocalExecutor()
    cp = contract.container
    if cp is not None:
        settings = ContainerSettings(
            image=cp.image,
            runtime=cp.runtime,
            network=cp.network,
            cpus=cp.cpus,
            memory_mb=cp.memory_mb,
            pids_limit=cp.pids_limit,
            tmpfs_mb=cp.tmpfs_mb,
            user=cp.user,
            env_passthrough=contract.env_passthrough,
        )
    elif opts.container_image:
        settings = ContainerSettings(
            image=opts.container_image, env_passthrough=contract.env_passthrough
        )
    else:
        raise ExecutorError("container execution requested but no image configured")
    return ContainerExecutor(settings)


def changed_production_lines(patch: Patch) -> dict[str, set[int]]:
    out: dict[str, set[int]] = {}
    for fc in patch.files:
        if fc.new_path and is_python(fc.new_path) and not is_test_path(fc.new_path) and fc.added:
            out[fc.new_path] = set(fc.added)
    return out


class _Collector:
    def __init__(
        self,
        repo: Repo,
        patch: Patch,
        contract: ReviewContract,
        opts: CollectOptions,
        executor: Executor,
    ) -> None:
        self.repo = repo
        self.patch = patch
        self.c = contract
        self.opts = opts
        self.ex = executor
        self.out = EvidenceOutcome()
        self.mode = "export" if executor.name == "container" else "worktree"
        if executor.name == "container":
            self.env: dict[str, str] = {}
        else:
            self.env, dropped = filtered_env(contract.env_passthrough)
            self.out.env_withheld = len(dropped)

    @contextmanager
    def _ws(self, commit: str) -> Iterator[Path]:
        with checkout(self.repo, commit, self.mode) as ws:
            yield ws

    def _run_all(
        self, specs: list[RequiredCheck], ws: Path, revision: str
    ) -> dict[str, EvidenceRun]:
        self.ex.workspace_ready(ws)
        runs: dict[str, EvidenceRun] = {}
        for spec in specs:
            run = run_check(spec, ws, self.env, executor=self.ex, revision=revision)
            runs[spec.name] = run
            self.out.runs.append(run)
        return runs

    def _overlay(
        self, ws: Path, items: tuple[TrustedEvidence, ...], commit_for_base: str
    ) -> list[Overlay]:
        overlays: list[Overlay] = []
        for t in items:
            if t.source == "base":
                # Trusted content always comes from the merge-base: the side of the patch
                # the candidate does not control, never from the head.
                entries = base_entries(self.repo, commit_for_base, t.paths)
                if not entries:
                    raise TrustedEvidenceError(
                        f"trusted evidence `{t.name}`: no files match {list(t.paths)} at base "
                        f"{commit_for_base[:12]}"
                    )
                overlays.append(overlay_base(ws, t.name, t.paths, entries))
            else:
                path = self.opts.bundles.get(t.name) or t.bundle_path
                if not path:
                    raise TrustedEvidenceError(
                        f"trusted evidence `{t.name}`: no bundle supplied "
                        f"(pass --bundle {t.name}=PATH)"
                    )
                assert t.digest is not None and t.mount is not None  # noqa: S101 - parser enforces
                entries = load_bundle(Path(path), t.digest)
                overlays.append(overlay_bundle(ws, t.name, t.mount, entries, t.digest))
        return overlays

    def collect(self) -> EvidenceOutcome:
        c = self.c
        head, base = self.patch.head, self.patch.base
        head_runs: dict[str, EvidenceRun] = {}
        base_runs: dict[str, EvidenceRun] = {}
        heads = list(c.required_checks)
        if heads:
            with self._ws(head) as ws:
                head_runs.update(self._run_all(heads, ws, "head"))
            diff = [s for s in heads if s.differential]
            if diff:
                with self._ws(base) as ws:
                    base_runs.update(self._run_all(diff, ws, "base"))
        if c.trusted_evidence:
            specs = [t.check for t in c.trusted_evidence]
            try:
                with self._ws(head) as ws:
                    self.out.overlays = self._overlay(ws, c.trusted_evidence, base)
                    head_runs.update(self._run_all(specs, ws, "head"))
                diff = [s for s in specs if s.differential]
                if diff:
                    with self._ws(base) as ws:
                        self._overlay(ws, c.trusted_evidence, base)
                        base_runs.update(self._run_all(diff, ws, "base"))
            except TrustedEvidenceError as exc:
                self.out.errors.append(GateError("trusted_evidence", str(exc)))
                specs = []
        for spec in c.external_evidence:
            run = ingest_external(spec, self.opts.external.get(spec.name))
            head_runs[spec.name] = run
            self.out.runs.append(run)
        for spec in [*heads, *[t.check for t in c.trusted_evidence], *c.external_evidence]:
            if spec.name in head_runs:
                self._judge(spec, head_runs[spec.name], base_runs.get(spec.name))
        return self.out

    # ------------------------------------------------------------------ judging

    def _stage(self, spec: RequiredCheck) -> str:
        return "trusted_evidence" if spec.source in ("base", "bundle") else "evidence"

    def _judge(self, spec: RequiredCheck, head: EvidenceRun, base: EvidenceRun | None) -> None:
        c = self.c
        label = f"`{spec.name}` ({spec.source} evidence)"
        entry: dict[str, Any] = {
            "name": spec.name,
            "source": spec.source,
            "required": spec.required,
            "head_status": head.status.value,
        }
        self.out.summary.append(entry)
        if head.status in UNAVAILABLE:
            msg = f"{label} {head.status.value}: {head.result.reason or 'no evidence produced'}"
            if spec.required:
                self.out.errors.append(GateError(self._stage(spec), msg))
            else:
                self.out.findings.append(finding("optional_evidence_unavailable", c, msg))
            return
        blocking = head.blocking_items()
        failed = head.status is ProviderStatus.FINDINGS
        hard_fail = failed and (
            bool(blocking) or head.report is None or head.report.format == "junit"
        )
        cls: DiffClass | None = None
        if base is not None:
            entry["base_status"] = base.status.value
            cls = classify(
                _effective(base),
                _effective(head),
                base.failure_identities(),
                head.failure_identities(),
            )
            entry["classification"] = cls.value
            if base.status in UNAVAILABLE:
                entry["base_reason"] = base.result.reason
        if hard_fail:
            self._failure(spec, head, cls, label)
        elif failed and head.report is not None:
            # Only non-blocking levels (e.g. SARIF warnings): a human should look.
            self.out.findings.append(
                finding(
                    "evidence_provider_findings",
                    c,
                    f"{label} reported {len(head.report.items)} finding(s) below the blocking "
                    f"level(s) {list(spec.block_levels)}",
                    severity=Severity.REVIEW,
                    after=_items_text(head),
                )
            )
        if head.report is not None and spec.min_changed_coverage is not None:
            self._coverage(spec, head, label)

    def _failure(
        self, spec: RequiredCheck, head: EvidenceRun, cls: DiffClass | None, label: str
    ) -> None:
        c = self.c
        detail = _items_text(head) or (head.result.output_tail[-300:] or None)
        if cls is None or cls in (DiffClass.NEW_REGRESSION, DiffClass.BASE_UNAVAILABLE):
            msg = f"{label} failed"
            msg += f" [{cls.value}]" if cls is not None else ""
            msg += f": {head.result.reason}"
            if spec.source in ("base", "bundle"):
                self.out.findings.append(finding("trusted_evidence_failed", c, msg, after=detail))
            elif head.report is not None and head.report.format != "junit":
                self.out.findings.append(
                    finding(
                        "evidence_provider_findings", c, msg, after=detail, severity=Severity.BLOCK
                    )
                )
            else:
                self.out.findings.append(finding("required_check_failed", c, msg, after=detail))
            return
        sev = severity_for(cls, spec.preexisting_failure, head_failed=True)
        if sev is None:
            return
        self.out.findings.append(
            finding(
                "preexisting_failure",
                c,
                f"{label} fails on head and on base [{cls.value}]; contract treats pre-existing "
                f"failures as `{spec.preexisting_failure}`. The failure is recorded, not cleared.",
                severity=sev,
                after=detail,
            )
        )

    def _coverage(self, spec: RequiredCheck, head: EvidenceRun, label: str) -> None:
        assert head.report is not None and spec.min_changed_coverage is not None  # noqa: S101
        changed = changed_production_lines(self.patch)
        covered, total, missing = changed_line_coverage(head.report, changed)
        if head.report.counts is not None:
            head.report.counts["changed_lines_covered"] = covered
            head.report.counts["changed_lines_total"] = total
        if total == 0:
            return
        ratio = covered / total
        if ratio < spec.min_changed_coverage:
            sample = ", ".join(f"{p}:{v[:5]}" for p, v in list(missing.items())[:3])
            self.out.findings.append(
                finding(
                    "changed_code_coverage_low",
                    self.c,
                    f"{label}: {covered}/{total} changed production lines executed "
                    f"({ratio:.0%} < {spec.min_changed_coverage:.0%}); uncovered: {sample}",
                )
            )


def _effective(run: EvidenceRun) -> ProviderStatus:
    """Status for differential comparison: FINDINGS only if something *blocking* failed."""
    if run.status is not ProviderStatus.FINDINGS:
        return run.status
    if run.report is None or run.report.format == "junit" or run.blocking_items():
        return ProviderStatus.FINDINGS
    return ProviderStatus.COMPLETE


def _items_text(run: EvidenceRun) -> str | None:
    if run.report is None or not run.report.items:
        return None
    lines = []
    for it in run.report.items[:5]:
        loc = f"{it.file}:{it.line}" if it.file and it.line else (it.file or "")
        lines.append(f"[{it.level}] {it.identity} {loc} {it.message[:80]}".strip())
    return "\n".join(lines)


def collect_evidence(
    repo: Repo, patch: Patch, contract: ReviewContract, opts: CollectOptions
) -> EvidenceOutcome:
    try:
        executor = build_executor(contract, opts)
        executor.prepare()
    except ExecutorError as exc:
        out = EvidenceOutcome()
        out.errors.append(GateError("execution", str(exc)))
        out.execution = {"executor": opts.executor or contract.executor, "error": str(exc)}
        return out
    col = _Collector(repo, patch, contract, opts, executor)
    out = col.collect()
    out.execution = executor.describe()
    return out


def trusted_paths_touched(patch: Patch, contract: ReviewContract) -> list[tuple[str, str]]:
    """(path, evidence name) for every changed path that falls under trusted evidence."""
    hits: list[tuple[str, str]] = []
    for fc in patch.files:
        for p in fc.paths:
            for t in contract.trusted_evidence:
                if (t.source == "base" and match_any(p, t.paths) is not None) or (
                    t.source == "bundle"
                    and t.mount
                    and (p == t.mount or p.startswith(t.mount + "/"))
                ):
                    hits.append((p, t.name))
    return hits
