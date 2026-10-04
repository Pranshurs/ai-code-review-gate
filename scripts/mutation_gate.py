"""Mutation gate for AICRG's own security-critical invariants.

This is deliberately *targeted*, not a coverage-maximising mutation run: each
mutant breaks one invariant the gate's correctness depends on, and the gate's
test suite must kill it. A surviving mutant means an invariant is unprotected.

Every mutation anchor must match exactly once, so mutants cannot silently rot
when the code changes (a missing anchor is a harness failure, not a pass).

Usage:  python scripts/mutation_gate.py [--only M03] [--json out.json]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GI = "tests/test_gate_invariants.py"
TI = "tests/test_test_integrity.py"
SC = "tests/test_security_ci_deps.py"
LL = "tests/test_llm_reviewer.py"
PO = "tests/test_policy.py"
TE = "tests/test_trusted_evidence.py"
PD = "tests/test_providers_differential.py"
EB = "tests/test_execution_boundary.py"
TP = "tests/test_potency.py"
AT = "tests/test_attestation.py"
DR = "tests/test_doctor.py"
SR = "tests/test_security_review_regressions.py"
PB = "tests/test_provenance_boundary.py"


@dataclass(frozen=True)
class Mutant:
    id: str
    invariant: str
    file: str
    find: str
    replace: str
    tests: tuple[str, ...]


MUTANTS: tuple[Mutant, ...] = (
    Mutant(
        "M01",
        "receipt is bound to the patch digest",
        "src/aicrg/receipt/verify.py",
        'and patch_digest(repo, merge_base, current_head) != subject.get("patch_digest")',
        "and False",
        (GI,),
    ),
    Mutant(
        "M02",
        "a changed HEAD invalidates a receipt",
        "src/aicrg/receipt/verify.py",
        'if subject.get("head") != current_head:',
        "if False:",
        (GI,),
    ),
    Mutant(
        "M03",
        "a failed command is FAIL, never PASS",
        "src/aicrg/evidence/commands.py",
        "        pstatus = ProviderStatus.FINDINGS\n    if preplanted:",
        "        pstatus = ProviderStatus.COMPLETE\n    if preplanted:",
        (GI,),
    ),
    Mutant(
        "M04",
        "deleted assertions are reported",
        "src/aicrg/testsafety/integrity.py",
        "if net_removed:",
        "if False:",
        (TI,),
    ),
    Mutant(
        "M05",
        "protected-path modification blocks",
        "src/aicrg/gate.py",
        "pat = match_any(p, c.protected_paths)",
        "pat = None",
        (GI,),
    ),
    Mutant(
        "M06",
        "malformed policy fails closed (unknown keys)",
        "src/aicrg/policy/contract.py",
        "unknown = sorted(set(data) - allowed)",
        "unknown: list[str] = []",
        (PO, GI),
    ),
    Mutant(
        "M07",
        "duplicate YAML keys are rejected",
        "src/aicrg/policy/contract.py",
        "        if key in seen:\n",
        "        if False:\n",
        (PO,),
    ),
    Mutant(
        "M08",
        "gate errors never become PASS",
        "src/aicrg/gate.py",
        "    if errors:\n        return Decision.ERROR",
        "    if False:\n        return Decision.ERROR",
        (GI,),
    ),
    Mutant(
        "M09",
        "an analyser exception is recorded as a gate error",
        "src/aicrg/gate.py",
        'self.errors.append(GateError(name, f"{type(exc).__name__}: {exc}"))',
        "pass",
        (GI,),
    ),
    Mutant(
        "M10",
        "a check timeout is ERROR",
        "src/aicrg/evidence/commands.py",
        "        pstatus = ProviderStatus.TIMEOUT\n",
        "        pstatus = ProviderStatus.COMPLETE\n",
        (GI,),
    ),
    Mutant(
        "M11",
        "a missing check executable is ERROR",
        "src/aicrg/evidence/executor.py",
        'return ExecOutcome(None, b"", start_error=f"executable not found: {argv[0]}")',
        'return ExecOutcome(0, b"")',
        (GI,),
    ),
    Mutant(
        "M12",
        "new runtime dependencies are evaluated",
        "src/aicrg/dependencies/delta.py",
        "            new_count += 1\n            _added(ctx, report, a)",
        "            new_count += 1",
        (SC,),
    ),
    Mutant(
        "M13",
        "a tampered receipt is rejected",
        "src/aicrg/receipt/verify.py",
        'if r.get("receipt_digest") != compute_digest(r):',
        "if False:",
        (GI,),
    ),
    Mutant(
        "M14",
        "a non-PASS receipt does not authorise a merge",
        "src/aicrg/receipt/verify.py",
        'if require_pass and r.get("decision") != "PASS":',
        "if False:",
        (GI,),
    ),
    Mutant(
        "M15",
        "a moved base branch makes the receipt stale",
        "src/aicrg/receipt/verify.py",
        'if cur_base != subject.get("base"):',
        "if False:",
        (GI,),
    ),
    Mutant(
        "M16",
        "policy is read from base, not head",
        "src/aicrg/gate.py",
        "load_policy(repo, base_sha, opts.policy, opts.policy_from)",
        "load_policy(repo, head_sha, opts.policy, opts.policy_from)",
        (GI,),
    ),
    Mutant(
        "M17",
        "inequality is weaker than equality",
        "src/aicrg/testsafety/assertions.py",
        "        if isinstance(op, (ast.NotEq, ast.IsNot)):\n            return 1,",
        "        if isinstance(op, (ast.NotEq, ast.IsNot)):\n            return 3,",
        (TI,),
    ),
    Mutant(
        "M18",
        "new unconditional skips are reported",
        "src/aicrg/testsafety/integrity.py",
        'if cls == "unconditional_skip":',
        'if cls == "never":',
        (TI,),
    ),
    Mutant(
        "M19",
        "CI failure masking is reported",
        "src/aicrg/testsafety/ci.py",
        "if MASK_RE.search(line):",
        "if False:",
        (SC,),
    ),
    Mutant(
        "M20",
        "removed authorization checks are reported",
        "src/aicrg/security/regressions.py",
        "if lost_auth:",
        "if False:",
        (SC,),
    ),
    Mutant(
        "M21",
        "secrets are redacted in findings",
        "src/aicrg/security/secrets.py",
        "after=redact(m.group(0)),",
        "after=m.group(0),",
        (SC,),
    ),
    Mutant(
        "M22",
        "credential env vars are withheld from checks",
        "src/aicrg/evidence/commands.py",
        "if SECRET_ENV_RE.search(k) and k not in passthrough:",
        "if False:",
        (GI,),
    ),
    Mutant(
        "M23",
        "reviewer hypotheses must cite an added line",
        "src/aicrg/llm/reviewer.py",
        "or line not in added[path]",
        "or False",
        (LL,),
    ),
    Mutant(
        "M24",
        "reviewer findings are capped at REVIEW",
        "src/aicrg/llm/reviewer.py",
        "sev = Severity.REVIEW if float(conf) >= REVIEW_CONFIDENCE else Severity.ADVISORY",
        "sev = Severity.BLOCK if float(conf) >= REVIEW_CONFIDENCE else Severity.ADVISORY",
        (LL,),
    ),
    Mutant(
        "M25",
        "evidence comes from the head commit, not the working tree",
        "src/aicrg/evidence/collect.py",
        'head_runs.update(self._run_all(heads, ws, "head"))',
        'head_runs.update(self._run_all(heads, self.repo.root, "head"))',
        (GI,),
    ),
    Mutant(
        "M26",
        "an internal CLI crash exits as ERROR",
        "src/aicrg/cli.py",
        '        print(f"aicrg: internal error: {type(exc).__name__}: {exc}", file=sys.stderr)\n'
        "        return EXIT[Decision.ERROR]",
        '        print(f"aicrg: internal error: {type(exc).__name__}: {exc}", file=sys.stderr)\n'
        "        return 0",
        (GI,),
    ),
    Mutant(
        "M27",
        "a blocking finding is FAIL",
        "src/aicrg/gate.py",
        "        return Decision.FAIL\n",
        "        return Decision.PASS\n",
        (GI,),
    ),
    # ---- trusted evidence ------------------------------------------------------------
    Mutant(
        "M28",
        "trusted evidence content comes from the base, never the candidate head",
        "src/aicrg/evidence/collect.py",
        'head_runs.update(self._trusted_runs(specs, head, "head", self.trusted_commit))',
        'head_runs.update(self._trusted_runs(specs, head, "head", head))',
        (f"{TE}::TestTrustedEvidenceDemo",),
    ),
    Mutant(
        "M29",
        "a trusted bundle whose digest differs is never used",
        "src/aicrg/evidence/trusted.py",
        "    if actual != expected_digest:",
        "    if False:",
        (f"{TE}::TestBundles",),
    ),
    Mutant(
        "M30",
        "candidate files under trusted paths are removed before the trusted run",
        "src/aicrg/evidence/trusted.py",
        "        if match_any(rel, patterns) is not None and rel not in entries:",
        "        if False:",
        (f"{TE}::TestTrustedEvidenceDemo",),
    ),
    Mutant(
        "M31",
        "a trusted overlay never writes through a symlink planted by the patch",
        "src/aicrg/evidence/workspace.py",
        "        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):",
        "        if False:",
        (EB,),
    ),
    # ---- test potency ----------------------------------------------------------------
    Mutant(
        "M32",
        "a surviving changed-code mutant is not treated as PASS",
        "src/aicrg/potency/engine.py",
        '    survivors = [r for r in rep.results if r.outcome == "survived"]',
        "    survivors: list[MutantResult] = []",
        (f"{TP}::TestPotencyGate",),
    ),
    Mutant(
        "M33",
        "a mutation engine error/timeout is never clean",
        "src/aicrg/potency/engine.py",
        '    if rep.status in ("ERROR", "TIMEOUT"):',
        "    if False:",
        (f"{TP}::TestPotencyGate",),
    ),
    Mutant(
        "M34",
        "a mutant is killed only when the tests fail",
        "src/aicrg/potency/engine.py",
        'outcome = "survived" if res.returncode == 0 else "killed"',
        'outcome = "killed"',
        (f"{TP}::TestPotencyGate",),
    ),
    # ---- differential evidence -------------------------------------------------------
    Mutant(
        "M35",
        "a new failure on top of pre-existing ones is a regression",
        "src/aicrg/evidence/differential.py",
        "    if any(n > base_ids.get(k, 0) for k, n in head_ids.items()):",
        "    if any(n > base_ids.get(k, 0) and k in base_ids for k, n in head_ids.items()):",
        (PD,),
    ),
    Mutant(
        "M36",
        "base PASS -> head FAIL is a new regression, never pre-existing",
        "src/aicrg/evidence/differential.py",
        "    if not base_failed:\n        return DiffClass.NEW_REGRESSION",
        "    if not base_failed:\n        return DiffClass.PRE_EXISTING_FAILURE",
        (PD,),
    ),
    Mutant(
        "M37",
        "'allow' covers only failures proven identical",
        "src/aicrg/evidence/differential.py",
        '    if cls is DiffClass.PRE_EXISTING_FAILURE and mode == "allow":',
        '    if mode == "allow":',
        (PD,),
    ),
    # ---- evidence providers ----------------------------------------------------------
    Mutant(
        "M38",
        "a required provider that is SKIPPED is not PASS",
        "src/aicrg/evidence/providers.py",
        "UNAVAILABLE = frozenset("
        "{ProviderStatus.SKIPPED, ProviderStatus.ERROR, ProviderStatus.TIMEOUT})",
        "UNAVAILABLE = frozenset({ProviderStatus.ERROR, ProviderStatus.TIMEOUT})",
        (PD,),
    ),
    Mutant(
        "M39",
        "a required provider that errors is not PASS",
        "src/aicrg/evidence/collect.py",
        "        if head.status in UNAVAILABLE:\n            msg",
        "        if False:\n            msg",
        (PD,),
    ),
    Mutant(
        "M40",
        "a report committed by the patch is discarded before the tool runs",
        "src/aicrg/evidence/commands.py",
        "            preplanted = safe_remove(cwd, check.report_path)",
        "            preplanted = False",
        (PD,),
    ),
    # ---- execution boundary ----------------------------------------------------------
    Mutant(
        "M41",
        "an operator cannot downgrade container execution to local",
        "src/aicrg/evidence/collect.py",
        '        if want == "container" and opts.executor == "local":',
        "        if False:",
        (EB,),
    ),
    Mutant(
        "M42",
        "container network is disabled unless the contract opts in",
        "src/aicrg/evidence/executor.py",
        '"none" if s.network == "none" else "bridge",',
        '"bridge",',
        (EB,),
    ),
    Mutant(
        "M43",
        "the host environment is not inherited by the container",
        "src/aicrg/evidence/executor.py",
        "            if name in self._host_env and name not in env:",
        "            if True:\n                env.update(self._host_env)\n"
        "            if name in self._host_env and name not in env:",
        (EB,),
    ),
    # ---- receipts / attestation ------------------------------------------------------
    Mutant(
        "M44",
        "an unsigned receipt is rejected when attestation is required",
        "src/aicrg/receipt/verify.py",
        '    if required and auth.status != "VERIFIED":',
        "    if False:",
        (AT,),
    ),
    Mutant(
        "M45",
        "an attestation for a different commit is rejected",
        "src/aicrg/receipt/attest.py",
        '    if expected_commit is None or cert.get("sourceRepositoryDigest") != expected_commit:',
        "    if False:",
        (AT,),
    ),
    Mutant(
        "M46",
        "a PR-ref signer workflow does not satisfy a protected-ref pin",
        "src/aicrg/receipt/attest.py",
        '        if cert.get("buildSignerURI") != want_signer:',
        "        if False:",
        (AT,),
    ),
    Mutant(
        "M47",
        "re-signing never leaves a stale signature in place",
        "src/aicrg/receipt/attest.py",
        "    sig.unlink(missing_ok=True)",
        "    pass",
        (AT,),
    ),
    # ---- doctor ----------------------------------------------------------------------
    Mutant(
        "M48",
        "doctor detects a missing gate workflow",
        "src/aicrg/doctor.py",
        "    if not gate_jobs:",
        "    if False:",
        (DR,),
    ),
    Mutant(
        "M49",
        "doctor detects a masked/disabled gate",
        "src/aicrg/doctor.py",
        "        if masked:",
        "        if False:",
        (DR,),
    ),
    Mutant(
        "M50",
        "doctor never reports unverifiable enforcement as PASS",
        "src/aicrg/doctor.py",
        '        if "UNKNOWN" in sts:\n            return "UNKNOWN"',
        '        if False:\n            return "UNKNOWN"',
        (DR,),
    ),
    # ---- cold security review fixes (docs/SECURITY_REVIEW.md) -------------------------
    Mutant(
        "M51",
        "F1: the verifier, not the receipt, decides which policy applies",
        "src/aicrg/receipt/verify.py",
        '            if policy_rec.get("source") != pol.source:',
        "            if False:",
        (AT,),
    ),
    Mutant(
        "M52",
        "F13: trusted content comes from the base tip, not the merge-base",
        "src/aicrg/gate.py",
        'trusted_commit=run.subject.get("base")',
        "trusted_commit=None",
        (f"{SR}::test_f13_trusted_content_comes_from_base_tip_not_stale_merge_base",),
    ),
    Mutant(
        "M53",
        "F3: trusted content changed during its own run is ERROR",
        "src/aicrg/evidence/collect.py",
        "                changed = scope.verify(ws)",
        "                changed: list[str] = []",
        (f"{SR}::test_f3_owner_restoring_write_permission_is_detected_local",),
    ),
    Mutant(
        "M54",
        "F3: trusted paths are mounted read-only in the container",
        "src/aicrg/evidence/executor.py",
        "        for rel in () if req.readonly_workspace else req.readonly:",
        "        for rel in ():",
        (EB,),
    ),
    Mutant(
        "M55",
        "F12: globs match paths containing newlines",
        "src/aicrg/globmatch.py",
        "    return re.compile(body, re.DOTALL)",
        "    return re.compile(body)",
        (f"{SR}::test_f12_globs_match_paths_with_newlines",),
    ),
    Mutant(
        "M56",
        "F12: changed paths with control characters block",
        "src/aicrg/gate.py",
        "            if has_control_chars(p):",
        "            if False:",
        (f"{SR}::test_f12_control_character_paths_block",),
    ),
    Mutant(
        "M57",
        "F4: exit 1 with a clean (or coverage) report is not PASS",
        "src/aicrg/evidence/commands.py",
        "    if pstatus is ProviderStatus.COMPLETE and rc == 1:",
        "    if False:",
        (f"{SR}::test_f4_coverage_tool_exit_1_is_not_pass",),
    ),
    Mutant(
        "M58",
        "F5: differential identities are a multiset",
        "src/aicrg/evidence/differential.py",
        "    if any(n > base_ids.get(k, 0) for k, n in head_ids.items()):",
        "    if any(k not in base_ids for k in head_ids):",
        (f"{SR}::test_f5_duplicate_identical_finding_is_a_new_regression",),
    ),
    Mutant(
        "M59",
        "F6a: a killed control mutant makes potency unmeasurable",
        "src/aicrg/potency/engine.py",
        "        if cres.start_error or cres.timed_out or cres.returncode != 0:",
        "        if False:",
        (f"{SR}::test_f6a_self_hash_test_cannot_fake_potency",),
    ),
    Mutant(
        "M60",
        "F6b: a truncated mutant sample is not COMPLETE",
        "src/aicrg/potency/engine.py",
        "    elif rep.sampled_from > rep.generated:",
        "    elif False:",
        (f"{SR}::test_f6b_truncated_sample_is_not_complete",),
    ),
    Mutant(
        "M61",
        "F7: test-named modules imported by production code are analysed",
        "src/aicrg/security/regressions.py",
        "        if fc.new_path is None or not ctx.is_production(fc.new_path):",
        "        if fc.new_path is None or is_test_path(fc.new_path):",
        (SR,),
    ),
    Mutant(
        "M62",
        "F8: doctor sees a gate whose exit status is piped away or ignored",
        "src/aicrg/doctor.py",
        '                masked += _gate_line_hazards(run_text, str(s.get("shell", "")))',
        "                masked += []",
        (SR,),
    ),
    Mutant(
        "M63",
        "F11: external evidence inside the evaluated checkout is refused",
        "src/aicrg/evidence/commands.py",
        "        if checkout_root is not None and "
        "p.resolve().is_relative_to(checkout_root.resolve()):",
        "        if False:",
        (f"{SR}::test_f11_external_report_inside_checkout_is_refused",),
    ),
    Mutant(
        "M64",
        "F11: external evidence for another revision is refused",
        "src/aicrg/evidence/commands.py",
        "        if report.revisions and expected_revisions and "
        "not (report.revisions & expected_revisions):",
        "        if False:",
        (f"{SR}::test_f11_external_report_for_another_revision_is_refused",),
    ),
    Mutant(
        "M65",
        "F9: XML must be UTF-8 so the DTD guard sees the text",
        "src/aicrg/evidence/providers.py",
        '        raise ReportError("XML report must be UTF-8") from exc',
        '        text = data.decode("latin-1")',
        (f"{SR}::test_f9_utf16_xml_with_entities_is_refused",),
    ),
    Mutant(
        "M66",
        "F1b: without --base the verifier cannot vouch for the base contract",
        "src/aicrg/receipt/verify.py",
        "        elif require_base:",
        "        elif False:",
        (f"{SR}::test_f1b_verify_without_base_cannot_vouch_for_contract",),
    ),
    Mutant(
        "M67",
        "N1: trusted runs see a read-only workspace in the container",
        "src/aicrg/evidence/collect.py",
        'readonly_workspace=self.ex.name == "container",',
        "readonly_workspace=False,",
        (f"{SR}::test_n1_trusted_run_sees_a_read_only_workspace",),
    ),
    Mutant(
        "M68",
        "N2: each changed function gets a behaviour-preserving control mutant",
        "src/aicrg/potency/mutators.py",
        "        *_function_controls(path, src, lines),",
        "",
        (f"{SR}::test_n2_function_bytecode_pin_cannot_fake_potency",),
    ),
    Mutant(
        "M69",
        "N3: string references (importlib/__import__/entry points) count as use",
        "src/aicrg/analysis/context.py",
        "            if (_imported_modules(tree, ref) | _string_refs(tree)) & names:",
        "            if _imported_modules(tree, ref) & names:",
        (SR,),
    ),
    Mutant(
        "M70",
        "N4: doctor flags a shell without errexit after the gate",
        "src/aicrg/doctor.py",
        '        if not errexit and (later or re.search(r";\\s*\\S", rest)):',
        "        if False:",
        (SR,),
    ),
    Mutant(
        "M71",
        "N5: require_revision refuses an unbound external report",
        "src/aicrg/evidence/commands.py",
        "        if check.require_revision and not report.revisions:",
        "        if False:",
        (f"{SR}::test_n5_require_revision_refuses_unbound_external_report",),
    ),
    Mutant(
        "M72",
        "a receipt's CI commit must be a merge built from its head",
        "src/aicrg/receipt/verify.py",
        "    if not sha or sha == head:",
        "    if True:",
        (f"{AT}::TestCiProvenance",),
    ),
    Mutant(
        "M73",
        "a GitHub attestation must sign the CI commit the gate ran on",
        "src/aicrg/receipt/attest.py",
        '    expected_commit = ((receipt.get("subject") or {}).get("ci") or {}).get("sha") or (',
        '    expected_commit = ({}).get("sha") or (',
        (f"{AT}::TestCiProvenance",),
    ),
    Mutant(
        "M74",
        "an unrelated CI commit is not an evidence revision for the head",
        "src/aicrg/gate.py",
        '    return ci.get("sha") if ci.get("relation") in ("head", "merge_of_head") else None',
        '    return ci.get("sha")',
        (PB,),
    ),
    Mutant(
        "M75",
        "a CI merge commit relates to the head only as the merge of exactly base and head",
        "src/aicrg/gate.py",
        '    return "merge_of_head" if parents == [base, head] else "unrelated"',
        '    return "merge_of_head" if head in parents else "unrelated"',
        (PB,),
    ),
    Mutant(
        "M76",
        "an ambient CI commit equal to nothing in the target is not related to the head",
        "src/aicrg/gate.py",
        '    if sha == head:\n        return "head"',
        '    if True:\n        return "head"',
        (PB,),
    ),
)


@dataclass
class Outcome:
    id: str
    invariant: str
    killed: bool
    seconds: float
    detail: str


def _workspace(tmp: Path) -> Path:
    ws = tmp / "ws"
    for rel in ("src", "tests", "pyproject.toml"):
        src = ROOT / rel
        if src.is_dir():
            shutil.copytree(src, ws / rel, ignore=shutil.ignore_patterns("__pycache__"))
        else:
            ws.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, ws / rel)
    return ws


def _env(ws: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{ws / 'src'}{os.pathsep}{ws}"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def _pytest(ws: Path, tests: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", *tests],
        cwd=ws,
        env=_env(ws),
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only")
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()
    mutants = [m for m in MUTANTS if not args.only or m.id == args.only]
    outcomes: list[Outcome] = []
    with tempfile.TemporaryDirectory(prefix="aicrg-mut-") as td:
        ws = _workspace(Path(td))
        probe = subprocess.run(
            [sys.executable, "-c", "import aicrg; print(aicrg.__file__)"],
            cwd=ws,
            env=_env(ws),
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        if not probe.startswith(str(ws)):
            print(f"harness error: aicrg imported from {probe}, not the mutation workspace")
            return 2
        for m in mutants:
            target = ws / m.file
            original = target.read_text()
            if original.count(m.find) != 1:
                print(f"harness error: {m.id} anchor matches {original.count(m.find)} times")
                return 2
        base = _pytest(ws, tuple(sorted({t for m in mutants for t in m.tests})))
        if base.returncode != 0:
            print("harness error: unmutated suite fails\n" + base.stdout[-2000:])
            return 2
        for m in mutants:
            target = ws / m.file
            original = target.read_text()
            target.write_text(original.replace(m.find, m.replace))
            t0 = time.perf_counter()
            try:
                proc = _pytest(ws, m.tests)
            finally:
                target.write_text(original)
            killed = proc.returncode != 0
            lines = [ln for ln in proc.stdout.splitlines() if ln.startswith("FAILED")]
            detail = lines[0][:160] if lines else proc.stdout.strip().splitlines()[-1][:160]
            outcomes.append(
                Outcome(m.id, m.invariant, killed, round(time.perf_counter() - t0, 1), detail)
            )
            print(
                f"{'KILLED  ' if killed else 'SURVIVED'} {m.id} {m.invariant:<55} "
                f"{outcomes[-1].seconds:>5}s  {detail if killed else ''}"[:220]
            )
    survived = [o.id for o in outcomes if not o.killed]
    print(
        f"\n{len(outcomes) - len(survived)}/{len(outcomes)} invariant mutants killed"
        + (f"; SURVIVED: {survived}" if survived else "")
    )
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps([asdict(o) for o in outcomes], indent=2) + "\n")
    return 1 if survived else 0


if __name__ == "__main__":
    raise SystemExit(main())
