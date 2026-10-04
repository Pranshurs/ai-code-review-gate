"""Compare AICRG with tampercheck and tamperguard on identical, frozen cases.

Pre-registered method (committed before the first run):

* Cases: corpus/dev, corpus/heldout, corpus/heldout-v2 (synthetic, built exactly
  as corpus/run_corpus.py builds them) and corpus/realworld (pinned upstream).
* Every tool sees the same patch: ``git diff --no-color --no-ext-diff
  <merge-base> <head>`` of the same repository.
* tampercheck 0.1.1: ``tampercheck`` reading the diff on stdin, default
  ``--min-severity high``. exit 0 = clean, 1 = flagged, 2 = tool error.
* tamperguard 0.2.0: ``tamperguard --json`` reading the diff on stdin.
  verdict ``tamper`` = flagged; ``review`` is reported separately and counted
  as flagged in the "tamper+review" view.
* AICRG: the full gate (synthetic corpora: each case's base contract and
  required checks; real-world: built-in default contract, no checks, decision
  without ``insufficient_evidence``, as in corpus/run_realworld.py).
  Flagged = decision is not PASS.
* Scope: tampercheck/tamperguard target verification tampering. A case is in
  the *overlap* scope when its category matches OVERLAP_RE (tests, assertions,
  skips, CI, golden data, suppressions, swallowed exceptions) or it is a
  legitimate case (false-positive measurement). All cases are reported; the
  overlap subset is where a like-for-like comparison is meaningful.

Usage: python scripts/baseline_compare.py --tools-venv /path/to/venv [--out DIR]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "corpus"))

import run_corpus  # noqa: E402
import run_realworld  # noqa: E402

from aicrg.gate import GateOptions, decide, run_gate  # noqa: E402

OVERLAP_RE = re.compile(
    r"test|assert|skip|xfail|\bci\b|ci_|ci:|golden|suppress|swallow|checker|pytest|"
    r"parametri|conftest|exception",
    re.I,
)


@dataclass
class Row:
    corpus: str
    id: str
    category: str
    bad: bool
    overlap: bool
    aicrg: str
    tampercheck: str  # flagged | clean | error
    tamperguard: str  # tamper | review | ok | error


def _diff(repo: Path, base: str, head: str) -> bytes:
    mb = subprocess.run(
        ["git", "merge-base", base, head], cwd=repo, capture_output=True, text=True, check=True
    ).stdout.strip()
    return subprocess.run(
        ["git", "diff", "--no-color", "--no-ext-diff", mb, head],
        cwd=repo,
        capture_output=True,
        check=True,
    ).stdout


def _tampercheck(venv: Path, diff: bytes, cwd: Path) -> str:
    p = subprocess.run(
        [str(venv / "bin" / "tampercheck")], input=diff, cwd=cwd, capture_output=True, check=False
    )
    return {0: "clean", 1: "flagged"}.get(p.returncode, "error")


def _tamperguard(venv: Path, diff: bytes, cwd: Path) -> str:
    p = subprocess.run(
        [str(venv / "bin" / "tamperguard"), "--json", "--fail-on", "never"],
        input=diff,
        cwd=cwd,
        capture_output=True,
        check=False,
    )
    try:
        verdict = json.loads(p.stdout.decode())["verdict"]
    except (ValueError, KeyError, TypeError):
        return "error"
    return verdict if verdict in ("tamper", "review", "ok") else "error"


def synthetic(corpus: str, venv: Path) -> list[Row]:
    rows: list[Row] = []
    for case_dir in sorted(p.parent for p in (ROOT / "corpus" / corpus).glob("*/case.yaml")):
        spec = yaml.safe_load((case_dir / "case.yaml").read_text())
        with tempfile.TemporaryDirectory(prefix="aicrg-cmp-") as td:
            repo = run_corpus.build_repo(case_dir, spec, Path(td))
            res = run_gate(GateOptions(base="main", head="HEAD"), cwd=repo)
            diff = _diff(repo, "main", "HEAD")
            bad = bool(spec.get("bad", True))
            cat = str(spec.get("category", ""))
            rows.append(
                Row(
                    corpus,
                    spec["id"],
                    cat,
                    bad,
                    (not bad) or bool(OVERLAP_RE.search(cat)),
                    res.decision.value,
                    _tampercheck(venv, diff, repo),
                    _tamperguard(venv, diff, repo),
                )
            )
        _show(rows[-1])
    return rows


def realworld(venv: Path, clones: Path) -> list[Row]:
    rows: list[Row] = []
    manifest = yaml.safe_load(run_realworld.MANIFEST.read_text())
    for case in manifest["cases"]:
        clone = run_realworld.clone_dir(clones, case["repo"])
        with run_realworld.CaseCheckout(clone, case) as (path, base, head):
            res = run_gate(GateOptions(base=base, head=head, run_checks=False), cwd=path)
            signal = [f for f in res.findings if f.code != "insufficient_evidence"]
            dec = decide(signal, res.errors).value
            diff = _diff(path, base, head)
            bad = bool(case["bad"])
            rows.append(
                Row(
                    "realworld",
                    case["id"],
                    case["category"],
                    bad,
                    (not bad) or bool(OVERLAP_RE.search(case["category"])),
                    dec,
                    _tampercheck(venv, diff, path),
                    _tamperguard(venv, diff, path),
                )
            )
        _show(rows[-1])
    return rows


def _show(r: Row) -> None:
    print(f"{r.corpus:<11} {r.id:<44} {r.aicrg:<16} {r.tampercheck:<8} {r.tamperguard}", flush=True)


def score(rows: list[Row]) -> dict[str, object]:
    def tool_flags(r: Row, tool: str, review_counts: bool = False) -> bool | None:
        v = getattr(r, tool)
        if v in ("error", "ERROR") and tool != "aicrg":
            return None
        if tool == "aicrg":
            return v != "PASS"
        if tool == "tampercheck":
            return v == "flagged"
        return v == "tamper" or (review_counts and v == "review")

    out: dict[str, object] = {}
    for label, subset in (("all", rows), ("overlap", [r for r in rows if r.overlap])):
        bad = [r for r in subset if r.bad]
        good = [r for r in subset if not r.bad]
        tools: dict[str, object] = {}
        for tool, rc in (
            ("aicrg", False),
            ("tampercheck", False),
            ("tamperguard", False),
            ("tamperguard", True),
        ):
            name = tool + ("+review" if rc else "")
            flags_bad = [tool_flags(r, tool, rc) for r in bad]
            flags_good = [tool_flags(r, tool, rc) for r in good]
            tools[name] = {
                "bad_detected": sum(1 for f in flags_bad if f),
                "bad_missed": sum(1 for f in flags_bad if f is False),
                "legit_flagged_false_positive": sum(1 for f in flags_good if f),
                "legit_clean": sum(1 for f in flags_good if f is False),
                "tool_errors": sum(1 for f in flags_bad + flags_good if f is None),
            }
        out[label] = {"bad": len(bad), "legitimate": len(good), "tools": tools}
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tools-venv", type=Path, required=True)
    ap.add_argument("--clones", type=Path, default=Path.home() / ".cache" / "aicrg-realworld")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--corpora", default="dev,heldout,heldout-v2,realworld")
    args = ap.parse_args()
    rows: list[Row] = []
    for c in args.corpora.split(","):
        rows += (
            realworld(args.tools_venv, args.clones)
            if c == "realworld"
            else synthetic(c, args.tools_venv)
        )
    per_corpus = {
        c: score([r for r in rows if r.corpus == c]) for c in sorted({r.corpus for r in rows})
    }
    summary = {"per_corpus": per_corpus, "combined": score(rows)}
    print(json.dumps(summary, indent=2))
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "baseline-comparison.json").write_text(
            json.dumps({"summary": summary, "rows": [asdict(r) for r in rows]}, indent=2) + "\n"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
