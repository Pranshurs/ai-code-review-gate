"""Run the gate over an adversarial patch corpus and report falsifiable results.

Usage:
    python corpus/run_corpus.py corpus/dev            # development/tuning set
    python corpus/run_corpus.py corpus/heldout        # held-out set (do not tune on it)

Each case directory contains ``case.yaml`` and optionally:
    base_files/   overlay applied to the fixture before the base commit
    files/        overlay applied for the agent's patch (head commit)
    after_files/  (kind: stale_receipt) an extra commit made after evaluation

case.yaml keys:
    id, fixture, category, task, agent_claim, kind (patch|stale_receipt),
    bad (bool), expect (list of acceptable decisions), expect_codes (list),
    delete (list of paths removed by the patch)
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
from dataclasses import asdict, dataclass, field
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "src"))

from aicrg.gate import GateOptions, run_gate  # noqa: E402
from aicrg.model import Severity  # noqa: E402
from aicrg.receipt.receipt import write_receipt  # noqa: E402
from aicrg.receipt.verify import verify_receipt  # noqa: E402

GIT_ENV = {
    "GIT_AUTHOR_NAME": "corpus",
    "GIT_AUTHOR_EMAIL": "corpus@example.invalid",
    "GIT_COMMITTER_NAME": "corpus",
    "GIT_COMMITTER_EMAIL": "corpus@example.invalid",
    "GIT_CONFIG_NOSYSTEM": "1",
}


@dataclass
class CaseResult:
    id: str
    category: str
    bad: bool
    expected: list[str]
    decision: str
    passed: bool
    codes: list[str] = field(default_factory=list)
    missing_codes: list[str] = field(default_factory=list)
    checks: dict[str, str] = field(default_factory=dict)
    note: str = ""
    seconds: float = 0.0


def git(cwd: Path, *args: str) -> str:
    env = {**os.environ, **GIT_ENV}
    out = subprocess.run(
        ["git", *args], cwd=cwd, env=env, capture_output=True, text=True, check=True
    )
    return out.stdout.strip()


def overlay(src: Path, dst: Path) -> None:
    if not src.is_dir():
        return
    for path in sorted(src.rglob("*")):
        if path.is_file():
            target = dst / path.relative_to(src)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)


def build_repo(case_dir: Path, spec: dict, tmp: Path) -> Path:
    fixture = ROOT / "fixtures" / spec["fixture"]
    if not fixture.is_dir():
        fixture = case_dir.parent.parent / "fixtures" / spec["fixture"]
    repo = tmp / "repo"
    shutil.copytree(
        fixture, repo, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache")
    )
    overlay(case_dir / "base_files", repo)
    git(repo, "init", "-q", "-b", "main")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "base")
    git(repo, "checkout", "-q", "-b", "agent")
    for rel in spec.get("delete", []) or []:
        target = repo / rel
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink()
    overlay(case_dir / "files", repo)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--allow-empty", "-m", f"agent: {spec.get('task', spec['id'])}")
    return repo


def run_case(case_dir: Path) -> CaseResult:
    spec = yaml.safe_load((case_dir / "case.yaml").read_text())
    t0 = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="aicrg-case-") as td:
        tmp = Path(td)
        repo = build_repo(case_dir, spec, tmp)
        result = run_gate(GateOptions(base="main", head="HEAD"), cwd=repo)
        codes = sorted({f.code for f in result.findings if f.severity is not Severity.ADVISORY})
        expected = list(spec["expect"])
        decision = result.decision.value
        missing = [c for c in spec.get("expect_codes", []) or [] if c not in codes]
        passed = decision in expected and not missing
        note = ""
        if spec.get("kind") == "stale_receipt":
            receipt_path = write_receipt(result.receipt, tmp / "receipts")
            before = verify_receipt(receipt_path, repo)
            overlay(case_dir / "after_files", repo)
            git(repo, "add", "-A")
            git(repo, "commit", "-q", "--allow-empty", "-m", "post-review change")
            after = verify_receipt(receipt_path, repo)
            tampered = json.loads(receipt_path.read_text())
            tampered["decision"] = "PASS" if decision != "PASS" else tampered["decision"]
            tampered["subject"]["head"] = git(repo, "rev-parse", "HEAD")
            receipt_path.write_text(json.dumps(tampered))
            forged = verify_receipt(receipt_path, repo)
            note = (
                f"verify before change ok={before.ok}; after new commit ok={after.ok} "
                f"({'; '.join(after.problems)[:120]}); forged head ok={forged.ok}"
            )
            passed = passed and before.ok and not after.ok and not forged.ok
            decision = f"{decision} / stale={'REJECTED' if not after.ok else 'ACCEPTED'}"
        if errors := [e.message for e in result.errors]:
            note = (note + " errors: " + "; ".join(errors))[:300]
    return CaseResult(
        id=spec["id"],
        category=spec.get("category", ""),
        bad=bool(spec.get("bad", True)),
        expected=expected,
        decision=decision,
        passed=passed,
        codes=codes,
        missing_codes=missing,
        checks={c.name: c.status.value for c in result.checks},
        note=note,
        seconds=round(time.perf_counter() - t0, 2),
    )


def summarize(results: list[CaseResult]) -> dict[str, object]:
    bad = [r for r in results if r.bad]
    good = [r for r in results if not r.bad]

    def blocked(r: CaseResult) -> bool:
        return not r.decision.startswith("PASS") or "stale=REJECTED" in r.decision

    return {
        "total": len(results),
        "bad_patches": len(bad),
        "bad_detected": sum(1 for r in bad if blocked(r)),
        "bad_missed": [r.id for r in bad if not blocked(r)],
        "bad_detected_as_FAIL": sum(1 for r in bad if r.decision.startswith("FAIL")),
        "bad_detected_as_REVIEW_REQUIRED": sum(
            1 for r in bad if r.decision.startswith("REVIEW_REQUIRED")
        ),
        "bad_detected_as_ERROR": sum(1 for r in bad if r.decision.startswith("ERROR")),
        "legitimate_patches": len(good),
        "legitimate_accepted": sum(1 for r in good if r.decision == "PASS"),
        "false_positives": [r.id for r in good if r.decision != "PASS"],
        "expectation_mismatches": [r.id for r in results if not r.passed],
        "bad_tests_green": sum(
            1 for r in bad if r.checks and all(v == "PASS" for v in r.checks.values())
        ),
    }


def to_markdown(name: str, results: list[CaseResult], summary: dict[str, object]) -> str:
    lines = [
        f"# Corpus results: {name}",
        "",
        "```",
        json.dumps(summary, indent=2),
        "```",
        "",
        "| case | category | bad | expected | decision | ok | tests | key findings |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        tests = ",".join(f"{k}={v}" for k, v in r.checks.items()) or "-"
        lines.append(
            f"| {r.id} | {r.category} | {'yes' if r.bad else 'no'} | {'/'.join(r.expected)} | "
            f"{r.decision} | {'✓' if r.passed else '✗'} | {tests} | "
            f"{', '.join(r.codes[:4]) or '-'}"
            f"{' MISSING ' + ','.join(r.missing_codes) if r.missing_codes else ''} |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus", type=Path)
    ap.add_argument("--out", type=Path, help="write <name>.json and <name>.md here")
    ap.add_argument("--only", help="run a single case id prefix")
    args = ap.parse_args()
    cases = sorted(p.parent for p in args.corpus.glob("*/case.yaml"))
    if args.only:
        cases = [c for c in cases if c.name.startswith(args.only)]
    results = []
    for c in cases:
        r = run_case(c)
        results.append(r)
        mark = "ok  " if r.passed else "MISS"
        print(f"{mark} {r.id:<40} {r.decision:<28} {','.join(r.codes[:5])} {r.note}"[:240])
    summary = summarize(results)
    print(json.dumps(summary, indent=2))
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        name = args.corpus.name
        (args.out / f"{name}.json").write_text(
            json.dumps({"summary": summary, "cases": [asdict(r) for r in results]}, indent=2) + "\n"
        )
        (args.out / f"{name}.md").write_text(to_markdown(name, results, summary))
    return 0 if not summary["expectation_mismatches"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
