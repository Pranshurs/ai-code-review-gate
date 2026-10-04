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
        "        status = CheckStatus.FAIL\n",
        "        status = CheckStatus.PASS\n",
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
        'status, reason = CheckStatus.ERROR, f"timed out',
        'status, reason = CheckStatus.PASS, f"timed out',
        (GI,),
    ),
    Mutant(
        "M11",
        "a missing check executable is ERROR",
        "src/aicrg/evidence/commands.py",
        "            CheckStatus.ERROR,\n            None,\n"
        "            started,\n            _now(),\n"
        "            round((clock() - t0) * 1000, 3),\n"
        '            "sha256:" + hashlib.sha256().hexdigest(),\n            "",\n'
        '            reason=f"executable not found',
        "            CheckStatus.PASS,\n            None,\n"
        "            started,\n            _now(),\n"
        "            round((clock() - t0) * 1000, 3),\n"
        '            "sha256:" + hashlib.sha256().hexdigest(),\n            "",\n'
        '            reason=f"executable not found',
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
        "src/aicrg/gate.py",
        "res = run_check(check, wt, env)",
        "res = run_check(check, repo.root, env)",
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
