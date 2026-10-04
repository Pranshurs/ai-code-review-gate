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
     bypass-gate-condition  `if: false` on the self-gate job (+ doctor)
   receipt challenges (on the self-review receipt):
     manipulate-receipt     edit the decision without resealing
     reseal-receipt         edit and recompute receipt_digest
     unsigned-required      verify with --require-attestation
     head-moved             a commit after review (stale receipt)
     change-subject         reseal the receipt claiming a different head
     attacker-signed        SSH-sign with a key outside allowed_signers
   evidence challenges (operator contract with one evidence item):
     provider-skipped       required external SARIF never supplied
     provider-error         required external SARIF corrupt
     bundle-digest          trusted bundle content differs from the pinned digest
     weaken-isolation       contract requires a container; operator asks for local
     unrelated-github-sha   ambient CI commit X of another repository, report bound to X

   controls (must be accepted, or the challenges above prove nothing):
     trusted-signed         SSH-signed with the allowed key
     report-for-head        external report bound to the evaluated head

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


# The challenges must not inherit the CI context of whatever runs this script.
AMBIENT_CI = (
    "GITHUB_ACTIONS",
    "GITHUB_SHA",
    "GITHUB_REPOSITORY",
    "GITHUB_REF",
    "GITHUB_EVENT_NAME",
)


def aicrg(
    cwd: Path, *args: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    base_env = {k: v for k, v in os.environ.items() if k not in AMBIENT_CI}
    return subprocess.run(
        [sys.executable, "-m", "aicrg", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        env={**base_env, **(env or {})},
    )


def check(
    cwd: Path, base: str, head: str, receipt: Path, *extra: str, env: dict[str, str] | None = None
) -> dict[str, object]:
    proc = aicrg(
        cwd, "check", "--base", base, "--head", head, "--receipt", str(receipt), *extra, env=env
    )
    r = json.loads(receipt.read_text())
    return {
        "exit_code": proc.returncode,
        "decision": r["decision"],
        "blocking": sorted({f["code"] for f in r["findings"] if f["severity"] == "block"}),
        "review": sorted({f["code"] for f in r["findings"] if f["severity"] == "review"}),
        "errors": [e["message"][:160] for e in r["errors"]],
        "checks": {c["name"]: c["provider_status"] for c in r["checks"]},
        "receipt_digest": r["receipt_digest"],
        "subject_head": r["subject"]["head"],
        "ci": r["subject"].get("ci"),
    }


class Challenges:
    def __init__(self, tmp: Path, head: str, self_receipt: Path, review_base: str) -> None:
        self.review_base = review_base
        self.tmp = tmp
        self.head = head
        self.self_receipt = self_receipt
        self.results: dict[str, dict[str, object]] = {}
        self.controls: dict[str, dict[str, object]] = {}
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
        self._doctor("weaken-gate-config")
        self._mutant("weaken-policy", weaken_policy, "--no-run")

        def bypass_condition(wt: Path) -> str:
            self._replace(
                wt / ".github/workflows/ci.yml",
                "  self-gate:\n    if: github.event_name == 'pull_request'\n",
                "  self-gate:\n    if: false  # temporarily disabled\n",
            )
            return "CI: pause the self-gate"

        self._mutant("bypass-gate-condition", bypass_condition, "--no-run")
        self._doctor("bypass-gate-condition")

    def _doctor(self, name: str) -> None:
        doc = aicrg(self.tmp / name, "doctor", "--format", "json")
        out = json.loads(doc.stdout)
        self.results[name]["doctor"] = {
            "exit_code": doc.returncode,
            "verdict": out["verdict"],
            "failing": [c["id"] for c in out["checks"] if c["status"] == "FAIL"],
        }

    def _verify(
        self, name: str, receipt: Path, cwd: Path, *extra: str, control: bool = False
    ) -> None:
        proc = aicrg(cwd, "verify-receipt", str(receipt), "--base", self.review_base, *extra)
        res = {
            "exit_code": proc.returncode,
            "decision": "REJECTED" if proc.returncode != 0 else "ACCEPTED",
            "output": proc.stdout.strip().splitlines()[:6],
        }
        (self.controls if control else self.results)[name] = res
        print(f"== {name:<24} {res['decision']}{'  (control)' if control else ''}")

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

        # Subject provenance: claim the reviewed patch was the post-review commit.
        moved = git("rev-parse", "HEAD", cwd=wt)
        p3 = self.tmp / "subject.json"
        p3.write_text(json.dumps(seal({**r, "subject": {**r["subject"], "head": moved}}), indent=2))
        self._verify("change-subject", p3, wt, "--head", moved)

        # Authenticity: a signature by a key that is not in allowed_signers.
        keys = {}
        for who in ("trusted", "attacker"):
            k = self.tmp / f"{who}-key"
            subprocess.run(
                ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", who, "-f", str(k)],
                check=True,
            )
            keys[who] = k
        allowed = self.tmp / "allowed_signers"
        allowed.write_text(f"gate@aicrg {(self.tmp / 'trusted-key.pub').read_text()}")
        ssh = ("--allowed-signers", str(allowed), "--identity", "gate@aicrg")
        for who, control in (("attacker", False), ("trusted", True)):
            p = self.tmp / f"{who}-signed.json"
            shutil.copy2(self.self_receipt, p)
            sign = aicrg(wt, "receipt", "sign", str(p), "--key", str(keys[who]))
            if sign.returncode != 0:
                raise SystemExit(f"signing failed: {sign.stdout}{sign.stderr}")
            self._verify(
                "trusted-signed" if control else "attacker-signed",
                p,
                wt,
                "--head",
                review_head,
                "--require-attestation",
                *ssh,
                control=control,
            )

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

        def run(
            name: str,
            policy: Path,
            *extra: str,
            env: dict[str, str] | None = None,
            control: bool = False,
        ) -> None:
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
                env=env,
            )
            (self.controls if control else self.results)[name] = res
            tag = "  (control)" if control else ""
            print(f"== {name:<24} {res['decision']:<16} {res['errors'][:1]}{tag}")

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

        iso = self.tmp / "container.yaml"
        iso.write_text(
            "version: 1\nexecution:\n  executor: container\n  container:\n"
            "    image: python:3.12-slim\nrequired_checks:\n"
            "  - name: noop\n    command: [python, -c, pass]\n"
        )
        run("weaken-isolation", iso, "--executor", "local")

        x = "e" * 40  # a commit of an unrelated runner repository
        ci_env = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_REPOSITORY": "other-org/runner",
            "GITHUB_SHA": x,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "push",
        }

        def sarif(rev: str) -> Path:
            f = self.tmp / f"{rev[:8]}.sarif"
            run_ = {
                "tool": {"driver": {"name": "codeql"}},
                "results": [],
                "versionControlProvenance": [{"repositoryUri": "u", "revisionId": rev}],
            }
            f.write_text(json.dumps({"version": "2.1.0", "runs": [run_]}))
            return f

        run("unrelated-github-sha", ext, "--evidence", f"codeql={sarif(x)}", env=ci_env)
        run(
            "report-for-head",
            ext,
            "--evidence",
            f"codeql={sarif(sha)}",
            env=ci_env,
            control=True,
        )
        self.evidence_head = sha


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
    summary["controls"] = ch.controls
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
    for name in ("weaken-test", "sabotage-with-trusted", "unrelated-github-sha"):
        shutil.copy2(tmp / f"{name}.json", OUT / f"{PREFIX}{name}-receipt.json")
    shutil.rmtree(tmp, ignore_errors=True)
    (OUT / f"{PREFIX}challenge.json").write_text(json.dumps(summary, indent=2) + "\n")
    blocked = all(r["decision"] in BLOCKING | {"REJECTED"} for r in ch.results.values())
    controls_ok = (
        ch.controls.get("trusted-signed", {}).get("decision") == "ACCEPTED"
        and ch.controls.get("report-for-head", {}).get("decision") == "PASS"
    )
    # The unrelated CI commit is recorded as execution provenance, never as the subject.
    u = ch.results.get("unrelated-github-sha", {})
    subject_kept = u.get("subject_head") == getattr(ch, "evidence_head", None) and (
        (u.get("ci") or {}).get("relation") == "unresolved"
    )
    doctor_flags = all(
        (ch.results.get(n, {}).get("doctor") or {}).get("verdict") not in (None, "PASS")
        for n in ("weaken-gate-config", "bypass-gate-condition")
    )
    summary["checks"] = {
        "all_challenges_blocked": blocked,
        "controls_accepted": controls_ok,
        "subject_not_replaced_by_ci_sha": subject_kept,
        "doctor_flags_weakened_workflows": doctor_flags,
    }
    ok = before == after and not any(reachable.values()) and blocked and controls_ok
    ok = ok and subject_kept and doctor_flags
    print(json.dumps({k: v for k, v in summary.items() if k != "restoration"}, indent=2)[:6000])
    leaked = any(reachable.values())
    print(f"restoration exact: {before == after}; challenge commits reachable: {leaked}")
    print("CHALLENGE PASSED" if ok else "CHALLENGE FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
