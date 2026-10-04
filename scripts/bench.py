"""Measure AICRG's own overhead, separately from the target project's tests.

Scenarios
  small   webapp fixture + a 2-file legitimate auth patch (corpus J02)
  large   this repository: root commit .. HEAD (the whole project as one patch)

For each scenario the gate runs N times with an operator policy that has NO
required checks, so the numbers are pure gate overhead (git, parsing, analysis,
receipt). Project test execution is measured separately (small scenario only)
because it belongs to the target repository, not to the gate.

Additional measurements (each reported separately, never folded into the
gate-overhead numbers):

  evidence_*        small scenario with ONE trivial check (python -c pass):
                    head checkout + run (local), the same as trusted evidence
                    (checkout + base overlay + run), and through the container
                    executor (if docker is available)
  receipt_*         ssh-keygen sign / verify-receipt with signature check
  potency           changed-code mutation on the small scenario with the
                    fixture's own pytest suite; cost scales with mutants x suite

Usage: python scripts/bench.py [-n 100] [--json docs/results/bench.json]
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import resource
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "corpus"))

import yaml  # noqa: E402
from run_corpus import build_repo  # noqa: E402

from aicrg.gate import GateOptions, run_gate  # noqa: E402
from aicrg.receipt.receipt import seal, write_receipt  # noqa: E402

STAGES = (
    "provenance",
    "policy",
    "patch",
    "risk",
    "contract",
    "test_integrity",
    "config",
    "suppressions",
    "ci_integrity",
    "security",
    "secrets",
    "dependencies",
    "evidence",
    "total",
)


def pct(values: list[float], p: float) -> float:
    s = sorted(values)
    k = (len(s) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return round(s[lo] + (s[hi] - s[lo]) * (k - lo), 3)


def summarise(values: list[float]) -> dict[str, float]:
    return {
        "n": len(values),
        "p50": pct(values, 0.50),
        "p95": pct(values, 0.95),
        "p99": pct(values, 0.99),
        "mean": round(statistics.fmean(values), 3),
        "max": round(max(values), 3),
    }


def bench(repo: Path, base: str, head: str, policy: Path, n: int) -> dict[str, object]:
    stage: dict[str, list[float]] = {s: [] for s in STAGES}
    receipt_ms: list[float] = []
    wall: list[float] = []
    opts = GateOptions(base=base, head=head, policy=str(policy), policy_from="file")
    run_gate(opts, cwd=repo)  # warm-up (imports, git object cache)
    tmp = Path(tempfile.mkdtemp(prefix="aicrg-bench-rc-"))
    for _ in range(n):
        t0 = time.perf_counter()
        res = run_gate(opts, cwd=repo)
        wall.append((time.perf_counter() - t0) * 1000)
        if res.decision.value == "ERROR":
            raise SystemExit(f"benchmark run errored: {res.errors}")
        for s in STAGES:
            stage[s].append(res.receipt["timings_ms"].get(s, 0.0))
        t1 = time.perf_counter()
        sealed = seal(res.receipt)
        write_receipt(sealed, tmp)
        receipt_ms.append((time.perf_counter() - t1) * 1000)
    shutil.rmtree(tmp, ignore_errors=True)
    tracemalloc.start()
    res = run_gate(opts, cwd=repo)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    files = res.receipt["subject"]["files"]
    return {
        "patch": {
            "files": len(files),
            "added_lines": sum(f["added_lines"] for f in files),
            "removed_lines": sum(f["removed_lines"] for f in files),
            "bytes": res.receipt["subject"]["patch_bytes"],
        },
        "decision": res.decision.value,
        "wall_ms": summarise(wall),
        "receipt_seal_and_write_ms": summarise(receipt_ms),
        "policy_evaluation_ms": summarise(
            [a + b for a, b in zip(stage["policy"], stage["contract"], strict=True)]
        ),
        "patch_analysis_ms": summarise(
            [
                sum(
                    stage[s][i]
                    for s in (
                        "patch",
                        "risk",
                        "test_integrity",
                        "config",
                        "suppressions",
                        "ci_integrity",
                        "security",
                        "secrets",
                        "dependencies",
                    )
                )
                for i in range(n)
            ]
        ),
        "stages_ms": {s: summarise(v) for s, v in stage.items() if any(v)},
        "python_heap_peak_mib": round(peak / 2**20, 2),
    }


def _timed_gate(repo: Path, policy: Path, n: int, **opts: object) -> dict[str, object]:
    o = GateOptions(base="main", head="HEAD", policy=str(policy), policy_from="file")
    for k, v in opts.items():
        setattr(o, k, v)
    first = run_gate(o, cwd=repo)
    if first.decision.value == "ERROR":
        return {"error": [e.message for e in first.errors]}
    wall, ev = [], []
    for _ in range(n):
        t0 = time.perf_counter()
        res = run_gate(o, cwd=repo)
        wall.append((time.perf_counter() - t0) * 1000)
        ev.append(res.receipt["timings_ms"].get("evidence", 0.0))
    return {"wall_ms": summarise(wall), "evidence_stage_ms": summarise(ev)}


def evidence_overheads(repo: Path, tmp: Path, n: int) -> dict[str, object]:
    py = sys.executable
    trivial = f"[{py!r}, -c, pass]"
    head_pol = tmp / "head.yaml"
    head_pol.write_text(f"version: 1\nrequired_checks:\n  - name: t\n    command: {trivial}\n")
    trusted_pol = tmp / "trusted.yaml"
    trusted_pol.write_text(
        "version: 1\ntrusted_evidence:\n  - name: t\n    source: base\n"
        f"    paths: [tests/**]\n    command: {trivial}\n"
    )
    out: dict[str, object] = {
        "evidence_head_trivial_check_local": _timed_gate(repo, head_pol, n),
        "evidence_trusted_trivial_check_local": _timed_gate(repo, trusted_pol, n),
    }
    if (
        shutil.which("docker")
        and subprocess.run(
            ["docker", "image", "inspect", "python:3.12-slim"], capture_output=True, check=False
        ).returncode
        == 0
    ):
        cont = tmp / "container.yaml"
        cont.write_text(
            "version: 1\nexecution:\n  executor: container\n  container:\n"
            "    image: python:3.12-slim\nrequired_checks:\n  - name: t\n"
            "    command: [python, -c, pass]\n"
        )
        out["evidence_head_trivial_check_container"] = _timed_gate(repo, cont, max(5, n // 5))
    else:
        out["evidence_head_trivial_check_container"] = "skipped: docker/image unavailable"
    return out


def receipt_overheads(repo: Path, tmp: Path, n: int) -> dict[str, object]:
    from aicrg.receipt.attest import ssh_sign
    from aicrg.receipt.verify import AttestationOptions, verify_receipt

    pol = tmp / "none.yaml"
    pol.write_text("version: 1\n")
    res = run_gate(GateOptions("main", "HEAD", str(pol), "file"), cwd=repo)
    path = write_receipt(res.receipt, tmp / "rc")
    out: dict[str, object] = {}
    plain = []
    for _ in range(n):
        t0 = time.perf_counter()
        verify_receipt(path, repo, require_pass=False)
        plain.append((time.perf_counter() - t0) * 1000)
    out["verify_receipt_ms"] = summarise(plain)
    if shutil.which("ssh-keygen") is None:
        out["ssh"] = "skipped: ssh-keygen unavailable"
        return out
    key = tmp / "k"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    signers = tmp / "allowed"
    signers.write_text("gate " + (tmp / "k.pub").read_text())
    sign, ver = [], []
    opts = AttestationOptions(require=True, allowed_signers=signers, identity="gate")
    for _ in range(n):
        t0 = time.perf_counter()
        ssh_sign(path, key)
        sign.append((time.perf_counter() - t0) * 1000)
        t0 = time.perf_counter()
        v = verify_receipt(path, repo, require_pass=False, attestation=opts)
        ver.append((time.perf_counter() - t0) * 1000)
        if v.authenticity.status != "VERIFIED":
            raise SystemExit(f"benchmark ssh verify failed: {v.problems}")
    out["ssh_sign_ms"] = summarise(sign)
    out["verify_receipt_with_ssh_signature_ms"] = summarise(ver)
    return out


def potency(repo: Path, tmp: Path, runs: int) -> dict[str, object]:
    pol = tmp / "potency.yaml"
    pol.write_text(
        "version: 1\ntest_potency:\n"
        f"  command: [{sys.executable!r}, -m, pytest, -q, -x, -p, no:cacheprovider]\n"
        "  max_mutants: 40\n"
    )
    walls, last = [], None
    for _ in range(runs):
        t0 = time.perf_counter()
        last = run_gate(GateOptions("main", "HEAD", str(pol), "file"), cwd=repo)
        walls.append((time.perf_counter() - t0) * 1000)
    assert last is not None
    tp = last.receipt["test_potency"]
    n_run = tp["killed"] + tp["killed_by_timeout"] + tp["survived"]
    return {
        "wall_ms": summarise(walls),
        "status": tp["status"],
        "changed_production_lines": tp["changed_production_lines"],
        "mutants_run": n_run,
        "equivalent": tp["equivalent"],
        "survived": tp["survived"],
        "ms_per_mutant_approx": round(statistics.fmean(walls) / max(1, n_run + 1), 1),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", type=int, default=100)
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()
    out: dict[str, object] = {
        "hardware": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "cpus": os.cpu_count(),
            "python": sys.version.split()[0],
            "git": subprocess.run(
                ["git", "--version"], capture_output=True, text=True, check=True
            ).stdout.strip(),
        },
        "method": "in-process run_gate(); operator policy with no required checks; "
        "1 warm-up run discarded; timings from receipt timings_ms and perf_counter",
    }
    with tempfile.TemporaryDirectory(prefix="aicrg-bench-") as td:
        tmp = Path(td)
        policy = tmp / "bench-policy.yaml"
        policy.write_text("version: 1\n")
        case = ROOT / "corpus" / "dev" / "J02-legit-auth-bugfix-with-tests"
        repo = build_repo(case, yaml.safe_load((case / "case.yaml").read_text()), tmp / "small")
        out["small"] = bench(repo, "main", "HEAD", policy, args.n)
        # Project test execution, measured separately: the fixture's own pytest run.
        tests = []
        for _ in range(max(5, args.n // 10)):
            t0 = time.perf_counter()
            subprocess.run(
                [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"],
                cwd=repo,
                capture_output=True,
                check=True,
            )
            tests.append((time.perf_counter() - t0) * 1000)
        out["small_project_tests_ms"] = summarise(tests)
        out.update(evidence_overheads(repo, tmp, max(10, args.n // 5)))
        out.update(receipt_overheads(repo, tmp, max(10, args.n // 5)))
        out["potency"] = potency(repo, tmp, 3)
        root_commit = subprocess.run(
            ["git", "rev-list", "--max-parents=0", "HEAD"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.split()[0]
        out["large"] = bench(ROOT, root_commit, "HEAD", policy, max(10, args.n // 5))
    out["process_max_rss_mib"] = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1)
    text = json.dumps(out, indent=2)
    print(text)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(text + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
