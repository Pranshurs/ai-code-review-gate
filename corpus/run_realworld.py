"""Run AICRG over the frozen real-world corpus (corpus/realworld/manifest.yaml).

Pre-registered method (committed before the first run; do not change after):

* Each case is materialised from a local clone of the pinned upstream repo:
  ``upstream``     base = manifest ``base``, head = manifest ``head``.
  ``inverted-fix`` base = ``fix_commit``, head = ``git revert --no-edit fix_commit``
                   committed on top of it (a mechanical reversal of a real fix).
* Contract: AICRG's built-in default contract (strict defaults, no required
  checks). Upstream test suites are NOT executed, so this track measures the
  static layer only: test integrity, CI integrity, security-regression,
  dependency and secret analysis. Trusted evidence, potency and differential
  execution are not exercised here.
* Two decisions are scored against ``acceptable`` and ``expect_strict``:
  ``decision``         the gate's decision as produced.
  ``signal_decision``  the decision recomputed without ``insufficient_evidence``
                       (that finding only says "no checks were configured",
                       which is true of every case under the default contract
                       and would otherwise turn every high-risk patch into
                       REVIEW_REQUIRED regardless of what the patch does).
* A bad case is *detected* when the decision is not PASS. A legitimate case is
  *accepted* when the decision is PASS. ERROR counts as neither accepted nor
  correct for legitimate cases.

Usage:
    python corpus/run_realworld.py [--clones DIR] [--out DIR] [--only RW05]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "src"))

from aicrg.gate import GateOptions, decide, run_gate  # noqa: E402
from aicrg.model import Severity  # noqa: E402

MANIFEST = ROOT / "realworld" / "manifest.yaml"
GIT_ENV = {
    "GIT_AUTHOR_NAME": "aicrg-eval",
    "GIT_AUTHOR_EMAIL": "eval@example.invalid",
    "GIT_COMMITTER_NAME": "aicrg-eval",
    "GIT_COMMITTER_EMAIL": "eval@example.invalid",
    "GIT_CONFIG_NOSYSTEM": "1",
}


def git(cwd: Path, *args: str, check: bool = True) -> str:
    out = subprocess.run(
        ["git", *args],
        cwd=cwd,
        env={**os.environ, **GIT_ENV},
        capture_output=True,
        text=True,
        check=False,
    )
    if check and out.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {out.stderr.strip()}")
    return out.stdout.strip()


@dataclass
class RWResult:
    id: str
    category: str
    bad: bool
    derivation: str
    acceptable: list[str]
    expect_strict: list[str]
    decision: str
    signal_decision: str
    ok: bool
    signal_ok: bool
    codes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    files: int = 0
    seconds: float = 0.0


def clone_dir(clones: Path, url: str) -> Path:
    name = url.rstrip("/").split("/")[-1].removesuffix(".git")
    path = clones / name
    if not path.is_dir():
        clones.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "clone", "-q", "--filter=blob:none", "--no-checkout", url, str(path)],
            check=True,
        )
    return path


class CaseCheckout:
    """A detached worktree of the case inside the shared clone; yields (path, base, head)."""

    def __init__(self, clone: Path, case: dict) -> None:
        self.clone = clone
        self.case = case
        self.tmp = Path(tempfile.mkdtemp(prefix="aicrg-rw-"))
        self.path = self.tmp / "wt"

    def __enter__(self) -> tuple[Path, str, str]:
        c = self.case
        start = c["fix_commit"] if c["derivation"] == "inverted-fix" else c["head"]
        git(self.clone, "worktree", "add", "-q", "--detach", "--force", str(self.path), start)
        if c["derivation"] == "inverted-fix":
            git(self.path, "revert", "--no-edit", c["fix_commit"])
            return self.path, c["fix_commit"], git(self.path, "rev-parse", "HEAD")
        return self.path, c["base"], c["head"]

    def __exit__(self, *exc: object) -> None:
        git(self.clone, "worktree", "remove", "--force", str(self.path), check=False)
        git(self.clone, "worktree", "prune", check=False)
        subprocess.run(["rm", "-rf", str(self.tmp)], check=False)


def run_case(case: dict, clones: Path) -> RWResult:
    t0 = time.perf_counter()
    clone = clone_dir(clones, case["repo"])
    with CaseCheckout(clone, case) as (path, base, head):
        res = run_gate(GateOptions(base=base, head=head, policy=None, run_checks=False), cwd=path)
    # The case repos have no AICRG contract at base, so the built-in default applies.
    signal = [f for f in res.findings if f.code != "insufficient_evidence"]
    signal_decision = decide(signal, res.errors).value
    decision = res.decision.value
    acc = list(case["acceptable"])
    return RWResult(
        id=case["id"],
        category=case["category"],
        bad=bool(case["bad"]),
        derivation=case["derivation"],
        acceptable=acc,
        expect_strict=list(case["expect_strict"]),
        decision=decision,
        signal_decision=signal_decision,
        ok=decision in acc,
        signal_ok=signal_decision in acc,
        codes=sorted({f.code for f in res.findings if f.severity is not Severity.ADVISORY}),
        errors=[f"{e.stage}: {e.message}"[:200] for e in res.errors],
        files=len(res.receipt.get("subject", {}).get("files", [])),
        seconds=round(time.perf_counter() - t0, 2),
    )


def summarize(results: list[RWResult]) -> dict[str, object]:
    bad = [r for r in results if r.bad]
    good = [r for r in results if not r.bad]

    def view(attr: str, ok_attr: str) -> dict[str, object]:
        return {
            "bad_detected": sum(1 for r in bad if getattr(r, attr) != "PASS"),
            "bad_total": len(bad),
            "bad_within_acceptable": sum(1 for r in bad if getattr(r, ok_attr)),
            "bad_missed": [r.id for r in bad if getattr(r, attr) == "PASS"],
            "legitimate_accepted_PASS": sum(1 for r in good if getattr(r, attr) == "PASS"),
            "legitimate_total": len(good),
            "legitimate_within_acceptable": sum(1 for r in good if getattr(r, ok_attr)),
            "legitimate_not_accepted": [r.id for r in good if getattr(r, attr) != "PASS"],
            "outside_acceptable": [r.id for r in results if not getattr(r, ok_attr)],
            "errors": [r.id for r in results if getattr(r, attr) == "ERROR"],
        }

    by_cat: dict[str, dict[str, int]] = {}
    for r in results:
        d = by_cat.setdefault(r.category, {"cases": 0, "signal_not_pass": 0})
        d["cases"] += 1
        d["signal_not_pass"] += r.signal_decision != "PASS"
    return {
        "total": len(results),
        "decision": view("decision", "ok"),
        "signal_decision": view("signal_decision", "signal_ok"),
        "by_category": by_cat,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--clones", type=Path, default=Path.home() / ".cache" / "aicrg-realworld")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--only")
    args = ap.parse_args()
    manifest = yaml.safe_load(MANIFEST.read_text())
    cases = [c for c in manifest["cases"] if not args.only or c["id"].startswith(args.only)]
    results: list[RWResult] = []
    for case in cases:
        try:
            r = run_case(case, args.clones)
        except Exception as exc:  # harness failure: record, never silently skip
            r = RWResult(
                case["id"],
                case["category"],
                bool(case["bad"]),
                case["derivation"],
                list(case["acceptable"]),
                list(case["expect_strict"]),
                "HARNESS_ERROR",
                "HARNESS_ERROR",
                False,
                False,
                errors=[f"{type(exc).__name__}: {exc}"[:300]],
            )
        results.append(r)
        print(
            f"{'ok ' if r.signal_ok else 'MISS'} {r.id:<46} {r.decision:<16} "
            f"signal={r.signal_decision:<16} {','.join(r.codes[:5])}"[:230],
            flush=True,
        )
    summary = summarize(results)
    print(json.dumps(summary, indent=2))
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "realworld.json").write_text(
            json.dumps({"summary": summary, "cases": [asdict(r) for r in results]}, indent=2) + "\n"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
