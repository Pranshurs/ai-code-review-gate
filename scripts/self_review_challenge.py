"""AICRG reviews its own changes, then is asked to accept a weakened copy of itself.

1. Snapshot the repository state (HEAD, index/worktree status, diff digest).
2. Self-review: `aicrg check --base <BASE> --head HEAD` with the policy at BASE.
3. Mutant: in a throwaway detached worktree, weaken one of AICRG's own invariant
   tests the way a coding agent might ("make the flaky test pass"), commit it, and
   run the gate on HEAD..mutant. Expected decision: FAIL.
4. Remove the worktree and verify the original repository is exactly restored.
5. Write receipts and a summary to docs/self-review/.

Usage: python scripts/self_review_challenge.py [--base SHA] [--no-run]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "self-review"
TARGET = "tests/test_gate_invariants.py"
ANCHOR = (
    "        res = gate()\n"
    "        assert res.decision is Decision.FAIL\n"
    '        assert "required_check_failed" in codes(res)\n'
)
MUTANT = (
    "        res = gate()\n"
    "        # flaky on CI runners; accept either outcome\n"
    "        assert res.decision in (Decision.FAIL, Decision.PASS)\n"
)


def git(*args: str, cwd: Path = ROOT) -> str:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "mutant-agent",
        "GIT_AUTHOR_EMAIL": "m@x.invalid",
        "GIT_COMMITTER_NAME": "mutant-agent",
        "GIT_COMMITTER_EMAIL": "m@x.invalid",
    }
    return subprocess.run(
        ["git", *args], cwd=cwd, env=env, capture_output=True, text=True, check=True
    ).stdout.strip()


def snapshot() -> dict[str, str]:
    return {
        "head": git("rev-parse", "HEAD"),
        "status": git("status", "--porcelain", "--untracked-files=all"),
        "diff_sha256": hashlib.sha256(
            subprocess.run(
                ["git", "diff", "HEAD", "--binary"], cwd=ROOT, capture_output=True, check=True
            ).stdout
        ).hexdigest(),
        "worktrees": git("worktree", "list", "--porcelain"),
    }


def aicrg(cwd: Path, base: str, head: str, receipt: Path, no_run: bool) -> tuple[int, dict]:
    cmd = [
        sys.executable,
        "-m",
        "aicrg",
        "check",
        "--base",
        base,
        "--head",
        head,
        "--receipt",
        str(receipt),
    ]
    if no_run:
        cmd.append("--no-run")
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
    print(proc.stdout)
    return proc.returncode, json.loads(receipt.read_text())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", help="default: the commit that introduced review-gate.yaml")
    ap.add_argument("--no-run", action="store_true", help="skip required checks (decision ERROR)")
    args = ap.parse_args()
    base = (
        args.base
        or git("log", "--diff-filter=A", "--format=%H", "--", "review-gate.yaml").splitlines()[-1]
    )
    before = snapshot()
    tmp = Path(tempfile.mkdtemp(prefix="aicrg-self-"))
    summary: dict[str, object] = {"base": base, "head": before["head"]}
    try:
        print(f"== self-review {base[:12]}..{before['head'][:12]}")
        rc, self_receipt = aicrg(ROOT, base, "HEAD", tmp / "self-review-receipt.json", args.no_run)
        summary["self_review"] = {
            "exit_code": rc,
            "decision": self_receipt["decision"],
            "reasons": self_receipt["reasons"],
            "receipt_digest": self_receipt["receipt_digest"],
        }

        wt = tmp / "mutant"
        git("worktree", "add", "-q", "--detach", str(wt), before["head"])
        target = wt / TARGET
        text = target.read_text()
        if text.count(ANCHOR) != 1:
            raise SystemExit("challenge anchor not found exactly once")
        target.write_text(text.replace(ANCHOR, MUTANT))
        git("commit", "-q", "-am", "Fix flaky gate test", cwd=wt)
        mutant_sha = git("rev-parse", "HEAD", cwd=wt)
        print(f"== mutant {mutant_sha[:12]}: weakened {TARGET}")
        rc_m, mutant_receipt = aicrg(
            wt, before["head"], mutant_sha, tmp / "mutant-receipt.json", args.no_run
        )
        summary["mutant"] = {
            "commit": mutant_sha,
            "exit_code": rc_m,
            "decision": mutant_receipt["decision"],
            "blocking": [f["code"] for f in mutant_receipt["findings"] if f["severity"] == "block"],
        }
    finally:
        if (tmp / "mutant").exists():
            git("worktree", "remove", "--force", str(tmp / "mutant"))
        git("worktree", "prune")
    after = snapshot()
    restored = before == after
    reachable = (
        git("branch", "-a", "--contains", summary.get("mutant", {}).get("commit", "HEAD"))
        if "mutant" in summary
        else ""
    )
    summary["restoration"] = {
        "exact": restored,
        "before": before,
        "after": after,
        "mutant_reachable_from_branches": reachable,
    }
    OUT.mkdir(parents=True, exist_ok=True)
    for name in ("self-review-receipt.json", "mutant-receipt.json"):
        if (tmp / name).exists():
            shutil.copy2(tmp / name, OUT / name)
    shutil.rmtree(tmp, ignore_errors=True)
    (OUT / "challenge.json").write_text(json.dumps(summary, indent=2) + "\n")
    ok = restored and not reachable and summary.get("mutant", {}).get("decision") == "FAIL"
    print(json.dumps({k: v for k, v in summary.items() if k != "restoration"}, indent=2))
    print(f"restoration exact: {restored}; mutant reachable: {bool(reachable)}")
    print("CHALLENGE PASSED" if ok else "CHALLENGE FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
