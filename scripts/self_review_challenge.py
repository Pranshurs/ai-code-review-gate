"""AICRG reviews its own changes, then must refuse adversarial copies of itself.

1. Snapshot the repository (HEAD, index/worktree status, diff digest, worktrees).
2. Self-review: ``aicrg check --base <REVIEW_BASE> --head <REVIEW_HEAD>`` with the
   contract at REVIEW_BASE, all required checks executed.
3. Challenges against HEAD, each in a throwaway worktree or temp file, each with
   an expected set of decisions (never PASS):

   patch challenges (gate on HEAD..mutant, contract read from HEAD):
     weaken-test            weaken one of AICRG's invariant tests ("flaky")
     sabotage-with-trusted  break receipt staleness in src AND weaken the invariant
                            test that would catch it (trusted evidence must fail)
     delete-trusted         delete the base-owned invariant test file
     weaken-gate-config     make the self-gate job continue-on-error (+ doctor)
     weaken-policy          drop trusted evidence from review-gate.yaml
   receipt challenges (on the self-review receipt):
     manipulate-receipt     edit the decision without resealing
     reseal-receipt         edit and recompute receipt_digest
     unsigned-required      verify with --require-attestation
     head-moved             a commit after review (stale receipt)
   evidence challenges (operator contract with one evidence item):
     provider-skipped       required external SARIF never supplied
     provider-error         required external SARIF corrupt
     bundle-digest          trusted bundle content differs from the pinned digest

4. Remove every worktree and verify the repository is exactly restored and no
   challenge commit is reachable from any branch.
5. Write receipts and a summary to docs/self-review/ (run3-*).

Patch challenges other than ``sabotage-with-trusted`` run with ``--no-run``:
their decision must come from patch analysis alone (BLOCK outranks the ERROR
that skipping evidence causes). ``weaken-test`` and ``sabotage-with-trusted``
execute every required check and trusted evidence.

Usage: python scripts/self_review_challenge.py --review-base SHA [--review-head REV]
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
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "self-review"
PREFIX = "run3-"
INVARIANTS = "tests/test_gate_invariants.py"
WEAK_ANCHOR = (
    "        res = gate()\n"
    "        assert res.decision is Decision.FAIL\n"
    '        assert "required_check_failed" in codes(res)\n'
)
WEAK_MUTANT = (
    "        res = gate()\n"
    "        # flaky on CI runners; accept either outcome\n"
    "        assert res.decision in (Decision.FAIL, Decision.PASS)\n"
)
STALE_SRC = "src/aicrg/receipt/verify.py"
STALE_ANCHOR = '        if subject.get("head") != current_head:\n'
STALE_MUTANT = "        if False:  # head comparison is redundant with the patch digest\n"
STALE_TEST_ANCHOR = (
    '        assert not v.ok\n        assert any("STALE" in p for p in v.problems)\n'
)
BLOCKING = {"FAIL", "REVIEW_REQUIRED", "ERROR"}


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
        "branches": git("for-each-ref", "--format=%(refname) %(objectname)", "refs/"),
    }


def aicrg(cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "aicrg", *args], cwd=cwd, capture_output=True, text=True, check=False
    )


def check(cwd: Path, base: str, head: str, receipt: Path, *extra: str) -> dict[str, object]:
    proc = aicrg(cwd, "check", "--base", base, "--head", head, "--receipt", str(receipt), *extra)
    r = json.loads(receipt.read_text())
    return {
        "exit_code": proc.returncode,
        "decision": r["decision"],
        "blocking": sorted({f["code"] for f in r["findings"] if f["severity"] == "block"}),
        "review": sorted({f["code"] for f in r["findings"] if f["severity"] == "review"}),
        "errors": [e["message"][:160] for e in r["errors"]],
        "checks": {c["name"]: c["provider_status"] for c in r["checks"]},
        "receipt_digest": r["receipt_digest"],
    }


class Challenges:
    def __init__(self, tmp: Path, head: str, self_receipt: Path, review_base: str) -> None:
        self.review_base = review_base
        self.tmp = tmp
        self.head = head
        self.self_receipt = self_receipt
        self.results: dict[str, dict[str, object]] = {}
        self.commits: list[str] = []

    def _mutant(self, name: str, edit: Callable[[Path], str], *extra: str) -> None:
        wt = self.tmp / name
        git("worktree", "add", "-q", "--detach", str(wt), self.head)
        msg = edit(wt)
        git("add", "-A", cwd=wt)
        git("commit", "-q", "-m", msg, cwd=wt)
        sha = git("rev-parse", "HEAD", cwd=wt)
        self.commits.append(sha)
        res = check(wt, self.head, sha, self.tmp / f"{name}.json", *extra)
        res["commit"] = sha
        res["message"] = msg
        self.results[name] = res
        print(f"== {name:<24} {res['decision']:<16} {res['blocking'] or res['review']}")

    @staticmethod
    def _replace(path: Path, old: str, new: str) -> None:
        text = path.read_text()
        if text.count(old) != 1:
            raise SystemExit(f"challenge anchor not found exactly once in {path}")
        path.write_text(text.replace(old, new))

    def patch_challenges(self) -> None:
        def weaken(wt: Path) -> str:
            self._replace(wt / INVARIANTS, WEAK_ANCHOR, WEAK_MUTANT)
            return "Fix flaky gate test"

        def sabotage(wt: Path) -> str:
            self._replace(wt / STALE_SRC, STALE_ANCHOR, STALE_MUTANT)
            self._replace(
                wt / INVARIANTS, STALE_TEST_ANCHOR, "        assert v.problems is not None\n"
            )
            return "Simplify receipt verification"

        def delete_trusted(wt: Path) -> str:
            (wt / INVARIANTS).unlink()
            return "Remove slow invariant tests"

        def weaken_ci(wt: Path) -> str:
            job = "  self-gate:\n    if: github.event_name == 'pull_request'\n"
            self._replace(
                wt / ".github/workflows/ci.yml", job, job + "    continue-on-error: true\n"
            )
            return "CI: do not block on the gate while it is in beta"

        def weaken_policy(wt: Path) -> str:
            p = wt / "review-gate.yaml"
            text = p.read_text()
            start = text.index("trusted_evidence:")
            end = text.index("\n\n", start)
            p.write_text(text[:start] + text[end + 2 :])
            return "Policy: drop redundant trusted evidence"

        self._mutant("weaken-test", weaken)
        self._mutant("sabotage-with-trusted", sabotage)
        self._mutant("delete-trusted", delete_trusted, "--no-run")
        self._mutant("weaken-gate-config", weaken_ci, "--no-run")
        doc = aicrg(self.tmp / "weaken-gate-config", "doctor", "--format", "json")
        self.results["weaken-gate-config"]["doctor"] = {
            "exit_code": doc.returncode,
            "verdict": json.loads(doc.stdout)["verdict"],
            "failing": [c["id"] for c in json.loads(doc.stdout)["checks"] if c["status"] == "FAIL"],
        }
        self._mutant("weaken-policy", weaken_policy, "--no-run")

    def _verify(self, name: str, receipt: Path, cwd: Path, *extra: str) -> None:
        proc = aicrg(cwd, "verify-receipt", str(receipt), "--base", self.review_base, *extra)
        self.results[name] = {
            "exit_code": proc.returncode,
            "decision": "REJECTED" if proc.returncode != 0 else "ACCEPTED",
            "output": proc.stdout.strip().splitlines()[:6],
        }
        print(f"== {name:<24} {self.results[name]['decision']}")

    def receipt_challenges(self, review_head: str) -> None:
        r = json.loads(self.self_receipt.read_text())
        p1 = self.tmp / "manipulated.json"
        p1.write_text(json.dumps({**r, "reasons": ["approved by maintainer"]}, indent=2))
        wt = self.tmp / "verify-at-review-head"
        git("worktree", "add", "-q", "--detach", str(wt), review_head)
        self._verify("manipulate-receipt", p1, wt, "--head", review_head)
        sys.path.insert(0, str(ROOT / "src"))
        from aicrg.receipt.receipt import seal

        p2 = self.tmp / "resealed.json"
        p2.write_text(json.dumps(seal({**r, "reasons": ["edited"]}), indent=2))
        self._verify("reseal-receipt", p2, wt, "--head", review_head, "--require-attestation")
        self._verify(
            "unsigned-required",
            self.self_receipt,
            wt,
            "--head",
            review_head,
            "--require-attestation",
        )
        (wt / "MOVED.txt").write_text("post-review change\n")
        git("add", "-A", cwd=wt)
        git("commit", "-q", "-m", "post-review change", cwd=wt)
        self.commits.append(git("rev-parse", "HEAD", cwd=wt))
        self._verify("head-moved", self.self_receipt, wt, "--head", "HEAD")

    def evidence_challenges(self) -> None:
        sys.path.insert(0, str(ROOT / "src"))
        from aicrg.evidence.trusted import bundle_from_bytes, read_bundle, tree_digest

        wt = self.tmp / "evidence"
        git("worktree", "add", "-q", "--detach", str(wt), self.head)
        (wt / "CHANGE.txt").write_text("x\n")
        git("add", "-A", cwd=wt)
        git("commit", "-q", "-m", "trivial change", cwd=wt)
        sha = git("rev-parse", "HEAD", cwd=wt)
        self.commits.append(sha)
        ext = self.tmp / "external.yaml"
        ext.write_text("version: 1\nexternal_evidence:\n  - name: codeql\n    format: sarif\n")

        def run(name: str, policy: Path, *extra: str) -> None:
            res = check(
                wt,
                self.head,
                sha,
                self.tmp / f"{name}.json",
                "--policy",
                str(policy),
                "--policy-from",
                "file",
                *extra,
            )
            self.results[name] = res
            print(f"== {name:<24} {res['decision']:<16} {res['errors'][:1]}")

        run("provider-skipped", ext)
        corrupt = self.tmp / "corrupt.sarif"
        corrupt.write_text('{"runs": [')
        run("provider-error", ext, "--evidence", f"codeql={corrupt}")
        bundle = self.tmp / "bundle.tar"
        bundle.write_bytes(bundle_from_bytes({"test_x.py": b"def test_x():\n    assert True\n"}))
        digest = tree_digest(read_bundle(bundle))
        pol = self.tmp / "bundle.yaml"
        pol.write_text(
            "version: 1\ntrusted_evidence:\n  - name: evals\n    source: bundle\n"
            f"    digest: {digest}\n    mount: evals\n    command: [python, -c, pass]\n"
        )
        bundle.write_bytes(bundle_from_bytes({"test_x.py": b"def test_x():\n    pass\n"}))
        run("bundle-digest", pol, "--bundle", f"evals={bundle}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--review-base", required=True)
    ap.add_argument("--review-head", default="HEAD")
    args = ap.parse_args()
    before = snapshot()
    review_head = git("rev-parse", args.review_head)
    tmp = Path(tempfile.mkdtemp(prefix="aicrg-self-"))
    summary: dict[str, object] = {
        "review_base": git("rev-parse", args.review_base),
        "review_head": review_head,
        "challenge_head": before["head"],
    }
    ch = Challenges(
        tmp, before["head"], tmp / "self-review-receipt.json", git("rev-parse", args.review_base)
    )
    try:
        print(f"== self-review {args.review_base[:12]}..{review_head[:12]}")
        wt = tmp / "review"
        git("worktree", "add", "-q", "--detach", str(wt), review_head)
        summary["self_review"] = check(
            wt,
            summary["review_base"],
            review_head,
            ch.self_receipt,  # type: ignore[arg-type]
        )
        print(f"   decision {summary['self_review']['decision']}")  # type: ignore[index]
        ch.patch_challenges()
        ch.receipt_challenges(review_head)
        ch.evidence_challenges()
    finally:
        for wt in tmp.iterdir():
            if wt.is_dir():
                subprocess.run(
                    ["git", "worktree", "remove", "--force", str(wt)],
                    cwd=ROOT,
                    capture_output=True,
                    check=False,
                )
        git("worktree", "prune")
    summary["challenges"] = ch.results
    after = snapshot()
    reachable = {c: git("branch", "-a", "--contains", c) for c in ch.commits}
    summary["restoration"] = {
        "exact": before == after,
        "before": before,
        "after": after,
        "challenge_commits_reachable_from_branches": {c: r for c, r in reachable.items() if r},
    }
    OUT.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ch.self_receipt, OUT / f"{PREFIX}self-review-receipt.json")
    for name in ("weaken-test", "sabotage-with-trusted"):
        shutil.copy2(tmp / f"{name}.json", OUT / f"{PREFIX}{name}-receipt.json")
    shutil.rmtree(tmp, ignore_errors=True)
    (OUT / f"{PREFIX}challenge.json").write_text(json.dumps(summary, indent=2) + "\n")
    blocked = all(r["decision"] in BLOCKING | {"REJECTED"} for r in ch.results.values())
    ok = before == after and not any(reachable.values()) and blocked
    print(json.dumps({k: v for k, v in summary.items() if k != "restoration"}, indent=2)[:6000])
    leaked = any(reachable.values())
    print(f"restoration exact: {before == after}; challenge commits reachable: {leaked}")
    print("CHALLENGE PASSED" if ok else "CHALLENGE FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
