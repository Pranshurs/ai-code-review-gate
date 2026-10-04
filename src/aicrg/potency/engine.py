"""Patch-aware test potency: would the submitted tests notice a wrong version of
the production code this patch changed?

Coverage says a changed line *executed*. Potency asks whether any assertion
*constrains* it: plausible wrong versions (mutants) of the changed lines are
generated, and the contract's test command is run against each one in a clean
checkout of the head, through the same executor as every other evidence
command.

Outcomes (``status`` in the receipt):

COMPLETE    every relevant mutant was killed (tests failed or timed out).
SURVIVORS   at least one mutant survived. This does **not** prove the patch is
            wrong; it shows the submitted evidence does not constrain that
            behaviour. Default REVIEW_REQUIRED (``on_survivor: fail`` blocks).
NO_MUTANTS  no mutation site on changed production lines (nothing to measure).
ERROR       the unmutated baseline failed, the engine/executor failed, or a run
TIMEOUT     exceeded the total budget before every mutant was tried.
            Never PASS: REVIEW_REQUIRED by default, ERROR with ``on_error: error``.

A mutant whose bytecode equals the original is *equivalent by construction*,
recorded, and not run. ``# pragma: no mutate`` on an added line is honoured but
reported (``test_potency_suppressed``): the patch cannot quietly opt out.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aicrg.analysis.context import is_production_path, is_python
from aicrg.evidence.collect import CollectOptions, build_executor
from aicrg.evidence.commands import filtered_env
from aicrg.evidence.executor import ExecRequest, Executor, ExecutorError
from aicrg.evidence.workspace import checkout, safe_write
from aicrg.git.diff import Patch
from aicrg.git.repo import Repo
from aicrg.globmatch import match_any
from aicrg.model import Finding, GateError, Severity
from aicrg.policy.contract import ReviewContract, TestPotencyPolicy
from aicrg.potency.mutators import Mutant, control_mutant, generate, sample
from aicrg.rules import finding

ENGINE = "aicrg-diffmut/1"


@dataclass(slots=True)
class MutantResult:
    mutant: Mutant
    outcome: str  # killed | survived | timeout | equivalent | not_run
    seconds: float = 0.0

    def to_json(self) -> dict[str, Any]:
        m = self.mutant
        return {
            "id": m.id,
            "file": m.file,
            "line": m.line,
            "operator": m.operator,
            "before": m.before,
            "after": m.after,
            "outcome": self.outcome,
            "seconds": round(self.seconds, 3),
        }


@dataclass(slots=True)
class PotencyReport:
    status: str = "NOT_RUN"
    changed_lines: int = 0
    files: list[str] = field(default_factory=list)
    results: list[MutantResult] = field(default_factory=list)
    generated: int = 0
    sampled_from: int = 0
    suppressed: dict[str, list[int]] = field(default_factory=dict)
    reason: str = ""
    seconds: float = 0.0
    seed: int | None = None
    findings: list[Finding] = field(default_factory=list)
    errors: list[GateError] = field(default_factory=list)

    def count(self, outcome: str) -> int:
        return sum(1 for r in self.results if r.outcome == outcome)

    def to_json(self) -> dict[str, Any]:
        return {
            "engine": ENGINE,
            "status": self.status,
            "reason": self.reason,
            "changed_production_lines": self.changed_lines,
            "files": self.files,
            "relevant_mutants": self.generated,
            "sampled_from": self.sampled_from,
            "sample_seed": self.seed,
            "killed": self.count("killed"),
            "killed_by_timeout": self.count("timeout"),
            "survived": self.count("survived"),
            "equivalent": self.count("equivalent"),
            "not_run": self.count("not_run"),
            "suppressed_lines": self.suppressed,
            "seconds": round(self.seconds, 3),
            "mutants": [r.to_json() for r in self.results[:200]],
        }


def _targets(repo: Repo, patch: Patch, pol: TestPotencyPolicy) -> dict[str, set[int]]:
    out: dict[str, set[int]] = {}
    for fc in patch.files:
        p = fc.new_path
        if not p or not fc.added or not is_python(p) or p.endswith(".pyi"):
            continue
        if not is_production_path(repo, patch.head, p):
            continue
        if match_any(p, pol.paths) is None:
            continue
        out[p] = set(fc.added)
    return out


def run_potency(
    repo: Repo,
    patch: Patch,
    contract: ReviewContract,
    opts: CollectOptions,
    *,
    executor: Executor | None = None,
) -> PotencyReport:
    pol = contract.test_potency
    assert pol is not None  # noqa: S101 - caller checked
    rep = PotencyReport()
    t0 = time.monotonic()
    try:
        _run(repo, patch, contract, pol, opts=opts, executor=executor, rep=rep, t0=t0)
    finally:
        rep.seconds = time.monotonic() - t0
    _judge(contract, pol, rep)
    return rep


def _run(
    repo: Repo,
    patch: Patch,
    contract: ReviewContract,
    pol: TestPotencyPolicy,
    *,
    opts: CollectOptions,
    executor: Executor | None,
    rep: PotencyReport,
    t0: float,
) -> None:
    targets = _targets(repo, patch, pol)
    rep.changed_lines = sum(len(v) for v in targets.values())
    rep.files = sorted(targets)
    all_mutants: list[Mutant] = []
    equivalent: list[Mutant] = []
    for path, lines in sorted(targets.items()):
        src = repo.read_blob(patch.head, path)
        if src is None:
            continue
        gen = generate(path, src, lines)
        if gen.parse_error:
            rep.status = "ERROR"
            rep.reason = f"cannot parse {path} to generate mutants: {gen.parse_error}"
            return
        all_mutants.extend(gen.mutants)
        equivalent.extend(gen.equivalent)
        if gen.suppressed_lines:
            rep.suppressed[path] = gen.suppressed_lines
    rep.results.extend(MutantResult(m, "equivalent") for m in equivalent)
    rep.sampled_from = len(all_mutants)
    rep.seed = secrets.randbits(32)
    chosen = sample(all_mutants, pol.max_mutants, rep.seed)
    rep.generated = len(chosen)
    if not chosen:
        rep.status = "NO_MUTANTS"
        rep.reason = (
            "no mutation sites on changed production lines"
            if rep.changed_lines
            else "patch changes no production Python lines"
        )
        return
    try:
        ex = executor or build_executor(contract, opts)
        ex.prepare()
    except ExecutorError as exc:
        rep.status, rep.reason = "ERROR", f"executor unavailable: {exc}"
        return
    if ex.name == "container":
        env: dict[str, str] = {}
    else:
        env, _ = filtered_env(contract.env_passthrough)
    mode = "export" if ex.name == "container" else "worktree"
    with checkout(repo, patch.head, mode) as ws:
        ex.workspace_ready(ws)
        base = ex.run(ExecRequest(pol.command, ws, env, pol.mutant_timeout_seconds * 3))
        if base.start_error or base.timed_out or base.returncode != 0:
            why = base.start_error or (
                "timed out" if base.timed_out else f"exit status {base.returncode}"
            )
            rep.status = "ERROR"
            rep.reason = f"unmutated baseline did not pass ({why}); potency cannot be measured"
            return
        originals: dict[str, bytes] = {}
        ctl = control_mutant(chosen[0].file, _read(ws, chosen[0].file))
        originals[ctl.file] = _read(ws, ctl.file)
        safe_write(ws, ctl.file, ctl.source)
        ex.workspace_ready(ws)
        try:
            cres = ex.run(ExecRequest(pol.command, ws, env, pol.mutant_timeout_seconds))
        finally:
            safe_write(ws, ctl.file, originals[ctl.file])
        if cres.start_error or cres.timed_out or cres.returncode != 0:
            rep.status = "ERROR"
            rep.reason = (
                "control mutant (behaviour unchanged, bytes changed) was killed: the tests "
                "depend on source text, so mutant kills prove nothing"
            )
            return
        for m in chosen:
            if time.monotonic() - t0 > pol.total_timeout_seconds:
                rep.results.append(MutantResult(m, "not_run"))
                continue
            originals.setdefault(m.file, _read(ws, m.file))
            safe_write(ws, m.file, m.source)
            ex.workspace_ready(ws)
            t1 = time.monotonic()
            try:
                res = ex.run(ExecRequest(pol.command, ws, env, pol.mutant_timeout_seconds))
            finally:
                safe_write(ws, m.file, originals[m.file])
            if res.start_error:
                rep.status = "ERROR"
                rep.reason = f"mutant run could not start: {res.start_error}"
                rep.results.append(MutantResult(m, "not_run"))
                return
            if res.timed_out:
                outcome = "timeout"
            else:
                outcome = "survived" if res.returncode == 0 else "killed"
            rep.results.append(MutantResult(m, outcome, time.monotonic() - t1))
    if rep.count("not_run"):
        rep.status = "TIMEOUT"
        rep.reason = (
            f"total budget {pol.total_timeout_seconds}s exhausted; "
            f"{rep.count('not_run')} mutant(s) not run"
        )
    elif rep.count("survived"):
        rep.status = "SURVIVORS"
    elif rep.sampled_from > rep.generated:
        rep.status = "SAMPLED"
        rep.reason = (
            f"only {rep.generated} of {rep.sampled_from} mutants were run (max_mutants); "
            "the unsampled behaviour is unmeasured"
        )
    else:
        rep.status = "COMPLETE"


def _read(ws: Path, rel: str) -> bytes:
    return (ws / rel).read_bytes()


def _judge(contract: ReviewContract, pol: TestPotencyPolicy, rep: PotencyReport) -> None:
    c = contract
    survivors = [r for r in rep.results if r.outcome == "survived"]
    sev = Severity.BLOCK if pol.on_survivor == "fail" else Severity.REVIEW
    for r in survivors[:10]:
        m = r.mutant
        rep.findings.append(
            finding(
                "test_potency_survivor",
                c,
                f"mutant {m.id} ({m.operator}) of changed code survived the submitted tests: "
                "the evidence does not constrain this behaviour",
                file=m.file,
                line=m.line,
                before=m.before,
                after=m.after,
                severity=sev,
            )
        )
    if len(survivors) > 10:
        rep.findings.append(
            finding(
                "test_potency_survivor",
                c,
                f"{len(survivors) - 10} more surviving mutant(s) (see receipt)",
                severity=sev,
            )
        )
    if rep.status == "SAMPLED":
        rep.findings.append(
            finding("test_potency_unavailable", c, f"test potency incomplete: {rep.reason}")
        )
    if rep.status in ("ERROR", "TIMEOUT"):
        msg = f"test potency {rep.status}: {rep.reason}"
        if pol.on_error == "error":
            rep.errors.append(GateError("test_potency", msg))
        else:
            rep.findings.append(finding("test_potency_unavailable", c, msg))
    for path, lines in sorted(rep.suppressed.items()):
        rep.findings.append(
            finding(
                "test_potency_suppressed",
                c,
                f"patch adds no-mutate pragma(s) on changed lines {lines[:10]}",
                file=path,
                line=lines[0],
            )
        )
