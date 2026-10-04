"""Security-critical invariants of the gate itself. The mutation gate
(scripts/mutation_gate.py) checks that each invariant here is killable."""

import json
import sys

import pytest

from aicrg.cli import main
from aicrg.gate import GateOptions, decide, run_gate
from aicrg.model import Decision, Finding, GateError, Kind, Severity
from aicrg.receipt.receipt import compute_digest, write_receipt
from aicrg.receipt.verify import verify_receipt
from tests.conftest import POLICY_NO_CHECKS, POLICY_PYTEST, codes

PY = sys.executable


def _f(sev: Severity) -> Finding:
    return Finding("x", "c", sev, Kind.DETERMINISTIC, "m")


class TestDecision:
    def test_matrix(self):
        assert decide([], []) is Decision.PASS
        assert decide([_f(Severity.ADVISORY)], []) is Decision.PASS
        assert decide([_f(Severity.REVIEW)], []) is Decision.REVIEW_REQUIRED
        assert decide([_f(Severity.BLOCK)], []) is Decision.FAIL
        assert decide([_f(Severity.BLOCK), _f(Severity.REVIEW)], []) is Decision.FAIL

    def test_error_never_passes(self):
        err = [GateError("s", "boom")]
        assert decide([], err) is Decision.ERROR
        assert decide([_f(Severity.ADVISORY)], err) is Decision.ERROR
        assert decide([_f(Severity.REVIEW)], err) is Decision.ERROR
        assert decide([_f(Severity.BLOCK)], err) is Decision.FAIL


def _base(repo, policy=POLICY_PYTEST):
    repo.commit(
        {
            "review-gate.yaml": policy,
            "src/m.py": "def add(a, b):\n    return a + b\n",
            "tests/test_m.py": "from src.m import add\n\ndef test_add():\n    assert add(1, 2) == 3\n",
            "src/__init__.py": "",
        }
    )
    repo.git("checkout", "-q", "-b", "agent")


class TestEvidence:
    def test_legit_patch_passes_with_executed_evidence(self, repo, gate):
        _base(repo)
        repo.commit({"src/m.py": "def add(a, b):\n    return b + a\n"})
        res = gate()
        assert res.decision is Decision.PASS
        assert [c.status.value for c in res.checks] == ["PASS"]

    def test_failed_command_is_fail_not_pass(self, repo, gate):
        _base(repo)
        repo.commit({"src/m.py": "def add(a, b):\n    return a - b\n"})
        res = gate()
        assert res.decision is Decision.FAIL
        assert "required_check_failed" in codes(res)

    def test_missing_executable_is_error(self, repo, gate):
        _base(repo, "version: 1\nrequired_checks: [definitely-missing-tool-xyz]\n")
        repo.commit({"src/m.py": "def add(a, b):\n    return b + a\n"})
        res = gate()
        assert res.decision is Decision.ERROR
        assert res.checks[0].status.value == "ERROR"

    def test_timeout_is_error(self, repo, gate):
        policy = (
            f"version: 1\nrequired_checks:\n  - name: slow\n"
            f"    command: [{PY!r}, -c, 'import time; time.sleep(30)']\n    timeout_seconds: 1\n"
        )
        _base(repo, policy)
        repo.commit({"README.md": "x"})
        res = gate()
        assert res.decision is Decision.ERROR

    def test_no_run_with_required_checks_is_error(self, repo, gate):
        _base(repo)
        repo.commit({"README.md": "x"})
        assert gate(run_checks=False).decision is Decision.ERROR

    def test_evidence_comes_from_head_commit_not_working_tree(self, repo, gate):
        _base(repo)
        repo.commit({"src/m.py": "def add(a, b):\n    return a - b\n"})  # broken, committed
        repo.write({"src/m.py": "def add(a, b):\n    return a + b\n"})  # fixed, uncommitted
        res = gate()
        assert res.decision is Decision.FAIL
        assert res.receipt["subject"]["working_tree_dirty"] is True

    def test_high_risk_without_checks_needs_review(self, repo, gate):
        repo.commit({"review-gate.yaml": POLICY_NO_CHECKS, "src/auth.py": "X = 1\n"})
        repo.git("checkout", "-q", "-b", "agent")
        repo.commit({"src/auth.py": "X = 2\n"})
        res = gate()
        assert "insufficient_evidence" in codes(res)
        assert res.decision is Decision.REVIEW_REQUIRED

    def test_secret_env_vars_are_withheld_from_checks(self, repo, gate, monkeypatch):
        monkeypatch.setenv("SUPER_SECRET_TOKEN", "hunter2")
        policy = (
            "version: 1\nrequired_checks:\n  - name: env\n"
            f"    command: [{PY!r}, -c, \"import os,sys; sys.exit('SUPER_SECRET_TOKEN' in os.environ)\"]\n"
        )
        _base(repo, policy)
        repo.commit({"README.md": "x"})
        assert gate().decision is Decision.PASS


class TestContractAndPolicy:
    def test_malformed_policy_is_error(self, repo, gate):
        _base(repo, "version: 1\nforbiden_changes: []\n")
        repo.commit({"README.md": "x"})
        res = gate()
        assert res.decision is Decision.ERROR
        assert any(e.stage == "policy" for e in res.errors)

    def test_patch_cannot_relax_its_own_policy(self, repo, gate):
        _base(repo, "version: 1\nprotected_paths: [src/**]\n")
        repo.commit({"review-gate.yaml": "version: 1\n", "src/m.py": "X = 1\n"})
        res = gate()
        assert "protected_path_modified" in codes(res)
        assert "policy_modified" in codes(res)
        assert res.decision is Decision.FAIL
        assert res.receipt["policy"]["source"] == "base:review-gate.yaml"

    def test_allowed_paths(self, repo, gate):
        _base(repo, "version: 1\nallowed_paths: [src/**, tests/**]\n")
        repo.commit({"scripts/x.sh": "echo hi\n"})
        assert "path_outside_contract" in codes(gate())

    def test_analyzer_crash_is_error_not_pass(self, repo, gate, monkeypatch):
        import aicrg.gate as g

        def boom(ctx):
            raise RuntimeError("analyser exploded")

        monkeypatch.setattr(g, "analyze_security", boom)
        _base(repo, POLICY_NO_CHECKS)
        repo.commit({"README.md": "x"})
        res = gate()
        assert res.decision is Decision.ERROR
        assert any("exploded" in e.message for e in res.errors)

    def test_not_a_repository_is_error(self, tmp_path):
        res = run_gate(GateOptions(base="main"), cwd=tmp_path)
        assert res.decision is Decision.ERROR

    def test_unknown_base_is_error(self, repo, gate):
        _base(repo, POLICY_NO_CHECKS)
        assert gate(base="no-such-branch").decision is Decision.ERROR


class TestReceipt:
    def _receipt(self, repo, gate, tmp_path):
        _base(repo, POLICY_NO_CHECKS)
        repo.commit({"README.md": "x"})
        res = gate()
        assert res.decision is Decision.PASS
        return write_receipt(res.receipt, tmp_path / "rc"), res

    def test_receipt_binds_exact_inputs(self, repo, gate, tmp_path):
        path, res = self._receipt(repo, gate, tmp_path)
        r = res.receipt
        assert r["schema"] == "aicrg.receipt/v2"
        assert r["subject"]["head"] == repo.git("rev-parse", "HEAD")
        assert r["subject"]["merge_base"] == repo.git("rev-parse", "main")
        assert r["subject"]["patch_digest"].startswith("sha256:")
        assert r["policy"]["contract_digest"].startswith("sha256:")
        assert r["receipt_digest"] == compute_digest(r)
        assert verify_receipt(path, repo.root).ok

    def test_new_commit_makes_receipt_stale(self, repo, gate, tmp_path):
        path, _ = self._receipt(repo, gate, tmp_path)
        repo.commit({"README.md": "changed after review"})
        v = verify_receipt(path, repo.root)
        assert not v.ok
        assert any("STALE" in p for p in v.problems)

    def test_tampered_receipt_rejected(self, repo, gate, tmp_path):
        path, _ = self._receipt(repo, gate, tmp_path)
        data = json.loads(path.read_text())
        data["findings"] = []
        data["timestamps"]["finished_at"] = "2000-01-01T00:00:00Z"
        path.write_text(json.dumps(data))
        assert not verify_receipt(path, repo.root).ok

    def test_resealed_receipt_with_forged_patch_digest_rejected(self, repo, gate, tmp_path):
        from aicrg.receipt.receipt import seal

        path, res = self._receipt(repo, gate, tmp_path)
        forged = dict(res.receipt)
        forged["subject"] = {**forged["subject"], "patch_digest": "sha256:" + "0" * 64}
        path.write_text(json.dumps(seal(forged)))
        v = verify_receipt(path, repo.root)
        assert not v.ok
        assert any("patch digest" in p for p in v.problems)

    def test_non_pass_receipt_does_not_authorise(self, repo, gate, tmp_path):
        _base(repo)
        repo.commit({"src/m.py": "def add(a, b):\n    return a - b\n"})
        res = gate()
        path = write_receipt(res.receipt, tmp_path / "rc")
        assert not verify_receipt(path, repo.root).ok

    def test_base_moved_or_policy_changed_is_stale(self, repo, gate, tmp_path):
        path, _ = self._receipt(repo, gate, tmp_path)
        repo.git("checkout", "-q", "main")
        repo.commit({"review-gate.yaml": "version: 1\nprotected_paths: [x/**]\n"})
        repo.git("checkout", "-q", "agent")
        v = verify_receipt(path, repo.root, base="main")
        assert not v.ok
        assert any("moved" in p for p in v.problems)
        assert any("policy" in p for p in v.problems)


class TestCli:
    def test_exit_codes(self, repo, monkeypatch, capsys):
        _base(repo)
        repo.commit({"src/m.py": "def add(a, b):\n    return a - b\n"})
        monkeypatch.chdir(repo.root)
        assert main(["check", "--base", "main", "--receipt-dir", "../rc"]) == 1
        repo.commit({"src/m.py": "def add(a, b):\n    return a + b\n"})
        assert main(["check", "--base", "main", "--receipt-dir", "../rc"]) == 0
        assert main(["check", "--base", "nope", "--receipt-dir", "../rc"]) == 4

    def test_internal_crash_is_error_exit(self, monkeypatch, capsys):
        import aicrg.gate as g

        def boom(*a, **k):
            raise RuntimeError("crash")

        monkeypatch.setattr(g, "run_gate", boom)
        assert main(["check", "--base", "main"]) == 4

    def test_verify_receipt_exit_code(self, repo, gate, tmp_path, monkeypatch):
        _base(repo, POLICY_NO_CHECKS)
        repo.commit({"README.md": "x"})
        path = write_receipt(gate().receipt, tmp_path / "rc")
        monkeypatch.chdir(repo.root)
        assert main(["verify-receipt", str(path), "--base", "main"]) == 0
        # Without --base the CLI refuses to vouch for the base contract.
        assert main(["verify-receipt", str(path)]) == 5
        assert main(["verify-receipt", str(path), "--no-base"]) == 0
        repo.commit({"README.md": "y"})
        assert main(["verify-receipt", str(path), "--base", "main"]) == 5

    def test_policy_validate(self, tmp_path, capsys):
        good = tmp_path / "p.yaml"
        good.write_text("version: 1\n")
        assert main(["policy", "validate", str(good)]) == 0
        good.write_text("version: 1\nnope: 1\n")
        assert main(["policy", "validate", str(good)]) == 4

    def test_terminal_escape_sequences_are_stripped(self):
        from aicrg.render import clean

        assert clean("ok\x1b[2J\x1b]0;pwned\x07done") == "okdone"


@pytest.mark.parametrize("n", [1, 2])
def test_receipt_digest_is_deterministic_for_same_inputs(repo, gate, n):
    _base(repo, POLICY_NO_CHECKS)
    repo.commit({"README.md": "x"})
    a, b = gate().receipt, gate().receipt
    for r in (a, b):
        r.pop("timestamps")
        r.pop("timings_ms")
        r.pop("receipt_digest")
    assert a == b


class TestExcludeFromAnalysis:
    POLICY = (
        "version: 1\nexclude_from_analysis: [corpus/**, .github/**]\n"
        "protected_paths: [corpus/frozen/**]\n"
    )

    def test_excluded_data_is_not_analysed(self, repo, gate):
        _base(repo, self.POLICY)
        repo.commit({"corpus/case/app.py": "import os\n\ndef f(x):\n    os.system(f'ls {x}')\n"})
        res = gate()
        assert "shell_injection_risk" not in codes(res)
        assert res.receipt["subject"]["files_excluded_from_analysis"] == 1

    def test_protected_paths_still_apply_to_excluded_files(self, repo, gate):
        _base(repo, self.POLICY)
        repo.commit({"corpus/frozen/x.txt": "changed"})
        assert "protected_path_modified" in codes(gate())

    def test_workflows_can_never_be_excluded(self, repo, gate):
        wf = "on: [pull_request]\njobs:\n  t:\n    runs-on: x\n    steps:\n      - run: pytest\n"
        repo.commit({"review-gate.yaml": self.POLICY, ".github/workflows/ci.yml": wf})
        repo.git("checkout", "-q", "-b", "agent")
        repo.commit({".github/workflows/ci.yml": wf.replace("pytest", "pytest || true")})
        assert "ci_failure_masked" in codes(gate())
