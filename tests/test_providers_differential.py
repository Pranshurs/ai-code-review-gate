"""Evidence providers (SARIF/JUnit/coverage/JSON) and base-vs-head differential evidence."""

import json
import sys
from pathlib import Path

import pytest

from aicrg.evidence.differential import DiffClass, classify, severity_for
from aicrg.evidence.providers import (
    ProviderStatus,
    ReportError,
    changed_line_coverage,
    parse_cobertura,
    parse_evidence_json,
    parse_junit,
    parse_lcov,
    parse_sarif,
)
from aicrg.model import Decision, Severity
from tests.conftest import codes

PY = sys.executable
P = ProviderStatus


def sarif(results, success=True):
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "t", "rules": [{"id": "R1"}]}},
                    "invocations": [{"executionSuccessful": success}],
                    "results": results,
                }
            ],
        }
    ).encode()


def res(rule="R1", level="error", uri="app/x.py", msg="bad", line=3):
    return {
        "ruleId": rule,
        "level": level,
        "message": {"text": msg},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}}
        ],
    }


class TestParsers:
    def test_sarif_statuses(self):
        assert parse_sarif(sarif([])).status is P.COMPLETE
        r = parse_sarif(sarif([res()]))
        assert r.status is P.FINDINGS and r.items[0].file == "app/x.py"
        assert parse_sarif(sarif([], success=False)).status is P.ERROR
        assert parse_sarif(json.dumps({"runs": []}).encode()).status is P.SKIPPED

    def test_sarif_identity_ignores_line_moves(self):
        a = parse_sarif(sarif([res(line=3)])).identities()
        b = parse_sarif(sarif([res(line=40)])).identities()
        assert a == b

    def test_sarif_suppressed_results_are_counted_not_hidden(self):
        r = parse_sarif(sarif([{**res(), "suppressions": [{"kind": "inSource"}]}]))
        assert r.status is P.COMPLETE and r.counts["suppressed"] == 1

    @pytest.mark.parametrize("data", [b"not json", b"{}", b'{"runs": [1]}'])
    def test_malformed_sarif_is_error(self, data):
        with pytest.raises(ReportError):
            parse_sarif(data)

    def test_junit(self):
        ok = b'<testsuite><testcase classname="a" name="t1"/></testsuite>'
        bad = (
            b'<testsuites><testsuite><testcase classname="a" name="t1">'
            b'<failure message="boom"/></testcase></testsuite></testsuites>'
        )
        none = b"<testsuite></testsuite>"
        skipped = b'<testsuite><testcase classname="a" name="t"><skipped/></testcase></testsuite>'
        assert parse_junit(ok).status is P.COMPLETE
        assert parse_junit(bad).status is P.FINDINGS
        assert parse_junit(bad).identities() == {"a::t1"}
        assert parse_junit(none).status is P.SKIPPED
        assert parse_junit(skipped).status is P.SKIPPED

    def test_xml_with_entities_is_refused(self):
        bomb = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><testsuite>&a;</testsuite>'
        with pytest.raises(ReportError):
            parse_junit(bomb)

    def test_coverage_formats_and_changed_lines(self):
        cob = (
            b"<coverage><sources><source>/ws</source></sources><packages><package><classes>"
            b'<class filename="app/x.py"><lines><line number="1" hits="1"/>'
            b'<line number="2" hits="0"/></lines></class></classes></package></packages></coverage>'
        )
        lcov = b"SF:/ws/app/x.py\nDA:1,1\nDA:2,0\nend_of_record\n"
        for rep in (parse_cobertura(cob, ("/ws",)), parse_lcov(lcov, ("/ws",))):
            assert rep.status is P.COMPLETE
            covered, total, missing = changed_line_coverage(
                rep, {"app/x.py": {1, 2}, "new.py": {5}}
            )
            assert (covered, total) == (1, 3)
            assert missing == {"app/x.py": [2], "new.py": [5]}

    def test_evidence_json(self):
        good = {"schema": "aicrg.evidence/v1", "status": "findings", "findings": [{"id": "x"}]}
        assert parse_evidence_json(json.dumps(good).encode()).status is P.FINDINGS
        for bad in (
            {"schema": "aicrg.evidence/v1", "status": "complete", "findings": [{"id": "x"}]},
            {"schema": "aicrg.evidence/v1", "status": "findings", "findings": []},
            {"schema": "other", "status": "complete"},
            {"schema": "aicrg.evidence/v1", "status": "ok"},
        ):
            with pytest.raises(ReportError):
                parse_evidence_json(json.dumps(bad).encode())


class TestClassify:
    def test_matrix(self):
        f = frozenset
        assert classify(P.COMPLETE, P.COMPLETE, None, None) is DiffClass.UNCHANGED_PASS
        assert classify(P.FINDINGS, P.COMPLETE, None, None) is DiffClass.FIXED_FAILURE
        assert classify(P.COMPLETE, P.FINDINGS, None, None) is DiffClass.NEW_REGRESSION
        assert classify(P.FINDINGS, P.FINDINGS, None, None) is DiffClass.BOTH_FAIL_UNCOMPARED
        assert (
            classify(P.FINDINGS, P.FINDINGS, f({"a", "b"}), f({"a"}))
            is DiffClass.PRE_EXISTING_FAILURE
        )
        assert classify(P.FINDINGS, P.FINDINGS, f({"a"}), f({"a", "c"})) is DiffClass.NEW_REGRESSION
        assert classify(P.ERROR, P.FINDINGS, None, None) is DiffClass.BASE_UNAVAILABLE
        assert classify(P.COMPLETE, P.TIMEOUT, None, None) is DiffClass.HEAD_UNAVAILABLE

    def test_severity(self):
        B, R, A = Severity.BLOCK, Severity.REVIEW, Severity.ADVISORY
        assert severity_for(DiffClass.NEW_REGRESSION, "allow", True) is B
        assert severity_for(DiffClass.BASE_UNAVAILABLE, "allow", True) is B
        assert severity_for(DiffClass.PRE_EXISTING_FAILURE, "fail", True) is B
        assert severity_for(DiffClass.PRE_EXISTING_FAILURE, "review", True) is R
        assert severity_for(DiffClass.PRE_EXISTING_FAILURE, "allow", True) is A
        # "allow" only covers failures proven identical
        assert severity_for(DiffClass.BOTH_FAIL_UNCOMPARED, "allow", True) is R
        assert severity_for(DiffClass.UNCHANGED_PASS, "fail", False) is None


# ---------------------------------------------------------------------------- end to end

LINT = """
import json, pathlib, sys
src = pathlib.Path("app/x.py").read_text()
results = [{"ruleId": "NOPE", "level": "error", "message": {"text": line.strip()},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app/x.py"},
                                                "region": {"startLine": i + 1}}}]}
           for i, line in enumerate(src.splitlines()) if "FIXME" in line]
pathlib.Path("out").mkdir(exist_ok=True)
pathlib.Path("out/lint.sarif").write_text(json.dumps({"version": "2.1.0", "runs": [
    {"tool": {"driver": {"name": "lint"}}, "results": results}]}))
sys.exit(1 if results else 0)
"""


def _lint_policy(mode="review", differential=True, required=True):
    return f"""
version: 1
required_checks:
  - name: lint
    command: [{PY!r}, tools/lint.py]
    differential: {str(differential).lower()}
    preexisting_failure: {mode}
    required: {str(required).lower()}
    report: {{format: sarif, path: out/lint.sarif}}
"""


def _lint_repo(repo, policy, code):
    repo.commit({"review-gate.yaml": policy, "tools/lint.py": LINT, "app/x.py": code})
    repo.git("checkout", "-q", "-b", "agent")


class TestDifferentialEndToEnd:
    def test_preexisting_failures_unchanged(self, repo, gate):
        _lint_repo(repo, _lint_policy("review"), "a = 1  # FIXME one\nb = 2  # FIXME two\n")
        repo.commit({"app/x.py": "a = 1  # FIXME one\nb = 2  # FIXME two\nc = 3\n"})
        res = _gate_ok(gate())
        assert res.decision is Decision.REVIEW_REQUIRED
        assert "preexisting_failure" in codes(res)
        ev = res.receipt["evidence"][0]
        assert ev["classification"] == "PRE_EXISTING_FAILURE"
        assert {c["revision"] for c in res.receipt["checks"]} == {"head", "base"}

    def test_preexisting_allowed_is_recorded_not_clean(self, repo, gate):
        _lint_repo(repo, _lint_policy("allow"), "a = 1  # FIXME one\n")
        repo.commit({"app/x.py": "a = 1  # FIXME one\nc = 3\n"})
        res = _gate_ok(gate())
        assert res.decision is Decision.PASS
        f = next(f for f in res.findings if f.code == "preexisting_failure")
        assert f.severity is Severity.ADVISORY
        assert res.receipt["checks"][0]["provider_status"] == "FINDINGS"

    def test_preexisting_fail_mode_blocks(self, repo, gate):
        _lint_repo(repo, _lint_policy("fail"), "a = 1  # FIXME one\n")
        repo.commit({"app/x.py": "a = 1  # FIXME one\nc = 3\n"})
        assert _gate_ok(gate()).decision is Decision.FAIL

    def test_new_failure_on_top_of_old_is_regression(self, repo, gate):
        _lint_repo(repo, _lint_policy("allow"), "a = 1  # FIXME one\n")
        repo.commit({"app/x.py": "a = 1  # FIXME one\nc = 3  # FIXME new\n"})
        res = _gate_ok(gate())
        assert res.decision is Decision.FAIL
        assert res.receipt["evidence"][0]["classification"] == "NEW_REGRESSION"

    def test_base_pass_head_fail_is_new_regression(self, repo, gate):
        _lint_repo(repo, _lint_policy("allow"), "a = 1\n")
        repo.commit({"app/x.py": "a = 1  # FIXME\n"})
        res = _gate_ok(gate())
        assert res.decision is Decision.FAIL
        assert "evidence_provider_findings" in codes(res)

    def test_fixed_failure_passes(self, repo, gate):
        _lint_repo(repo, _lint_policy("fail"), "a = 1  # FIXME\n")
        repo.commit({"app/x.py": "a = 1\n"})
        res = _gate_ok(gate())
        assert res.decision is Decision.PASS
        assert res.receipt["evidence"][0]["classification"] == "FIXED_FAILURE"

    def test_exit_status_only_both_fail_is_uncompared_review(self, repo, gate):
        pol = f"""
version: 1
required_checks:
  - name: t
    command: [{PY!r}, -c, "import sys; sys.exit(1)"]
    differential: true
    preexisting_failure: allow
"""
        repo.commit({"review-gate.yaml": pol, "a.py": "x = 1\n"})
        repo.git("checkout", "-q", "-b", "agent")
        repo.commit({"a.py": "x = 2\n"})
        res = _gate_ok(gate())
        assert res.decision is Decision.REVIEW_REQUIRED
        assert res.receipt["evidence"][0]["classification"] == "BOTH_FAIL_UNCOMPARED"


def _gate_ok(res):
    """The policy must have loaded: an ERROR from a broken test policy proves nothing."""
    assert res.receipt["policy"] is not None
    assert not any(e.stage == "policy" for e in res.errors), res.errors
    return res


class TestProviderFailClosed:
    def _repo(self, repo, script, fmt="sarif", path="out/r.sarif", extra=""):
        pol = f"""
version: 1
required_checks:
  - name: scan
    command: [{PY!r}, tools/scan.py]
    report: {{format: {fmt}, path: {path}}}
{extra}"""
        repo.commit({"review-gate.yaml": pol, "a.py": "x = 1\n", "tools/scan.py": script})
        repo.git("checkout", "-q", "-b", "agent")

    @staticmethod
    def writer(body: str, path: str = "out/r.sarif") -> str:
        return (
            f"import os\nos.makedirs('out', exist_ok=True)\nopen({path!r}, 'w').write({body!r})\n"
        )

    def test_missing_report_is_error(self, repo, gate):
        self._repo(repo, "pass\n")
        repo.commit({"a.py": "x = 2\n"})
        assert _gate_ok(gate()).decision is Decision.ERROR

    def test_preplanted_report_is_discarded(self, repo, gate):
        self._repo(repo, "pass\n")
        clean = sarif([]).decode()
        repo.commit({"a.py": "x = 2\n", "out/r.sarif": clean})
        res = _gate_ok(gate())
        assert res.decision is Decision.ERROR  # tool wrote nothing; planted file was removed
        assert "committed by the patch" in res.checks[0].reason

    def test_symlinked_report_is_error(self, repo, gate, tmp_path):
        fake = tmp_path / "clean.sarif"
        fake.write_bytes(sarif([]))
        cmd = f"import os\nos.makedirs('out', exist_ok=True)\nos.symlink({str(fake)!r}, 'out/r.sarif')\n"
        self._repo(repo, cmd)
        repo.commit({"a.py": "x = 2\n"})
        res = _gate_ok(gate())
        assert res.decision is Decision.ERROR
        assert "not a regular file" in res.checks[0].reason

    def test_tool_crash_exit_code_is_error(self, repo, gate):
        self._repo(repo, "import sys\nsys.exit(2)\n")
        repo.commit({"a.py": "x = 2\n"})
        assert _gate_ok(gate()).decision is Decision.ERROR

    def test_sarif_execution_failed_is_error(self, repo, gate):
        self._repo(repo, self.writer(sarif([], success=False).decode()))
        repo.commit({"a.py": "x = 2\n"})
        assert _gate_ok(gate()).decision is Decision.ERROR

    def test_warning_level_findings_need_review(self, repo, gate):
        self._repo(repo, self.writer(sarif([res(level="warning")]).decode()))
        repo.commit({"a.py": "x = 2\n"})
        res_ = _gate_ok(gate())
        assert res_.decision is Decision.REVIEW_REQUIRED
        assert "evidence_provider_findings" in codes(res_)

    def test_junit_no_tests_is_skipped_and_required_skip_is_error(self, repo, gate):
        cmd = self.writer("<testsuite></testsuite>", "out/j.xml")
        self._repo(repo, cmd, fmt="junit", path="out/j.xml")
        repo.commit({"a.py": "x = 2\n"})
        res_ = _gate_ok(gate())
        assert res_.decision is Decision.ERROR
        assert res_.checks[0].provider_status == "SKIPPED"

    def test_optional_skipped_provider_is_advisory(self, repo, gate):
        cmd = self.writer("<testsuite></testsuite>", "out/j.xml")
        self._repo(repo, cmd, fmt="junit", path="out/j.xml")
        pol = (
            (repo.root / "review-gate.yaml")
            .read_text()
            .replace("    report:", "    required: false\n    report:")
        )
        repo.git("checkout", "-q", "main")
        repo.commit({"review-gate.yaml": pol})
        repo.git("checkout", "-q", "agent")
        repo.git("merge", "-q", "main")
        repo.commit({"a.py": "x = 2\n"})
        res_ = _gate_ok(gate())
        assert res_.decision is Decision.PASS
        assert "optional_evidence_unavailable" in codes(res_, include_advisory=True)

    def test_timeout_is_error(self, repo, gate):
        pol = f"""
version: 1
required_checks:
  - name: slow
    command: [{PY!r}, -c, "import time; time.sleep(30)"]
    timeout_seconds: 1
"""
        repo.commit({"review-gate.yaml": pol, "a.py": "x = 1\n"})
        repo.git("checkout", "-q", "-b", "agent")
        repo.commit({"a.py": "x = 2\n"})
        res_ = _gate_ok(gate())
        assert res_.decision is Decision.ERROR
        assert res_.checks[0].provider_status == "TIMEOUT"


class TestExternalEvidence:
    POL = """
version: 1
external_evidence:
  - name: codeql
    format: sarif
"""

    def _repo(self, repo):
        repo.commit({"review-gate.yaml": self.POL, "a.py": "x = 1\n"})
        repo.git("checkout", "-q", "-b", "agent")
        repo.commit({"a.py": "x = 2\n"})

    def test_missing_required_external_report_is_error(self, repo, gate):
        self._repo(repo)
        res = _gate_ok(gate())
        assert res.decision is Decision.ERROR
        assert res.checks[0].provider_status == "SKIPPED"

    def test_clean_external_report_passes(self, repo, gate, tmp_path):
        self._repo(repo)
        p = tmp_path / "codeql.sarif"
        p.write_bytes(sarif([]))
        res = _gate_ok(gate(external_evidence={"codeql": str(p)}))
        assert res.decision is Decision.PASS
        assert res.checks[0].source == "external" and res.checks[0].report_digest

    def test_external_findings_block(self, repo, gate, tmp_path):
        self._repo(repo)
        p = tmp_path / "codeql.sarif"
        p.write_bytes(sarif([res()]))
        res_ = _gate_ok(gate(external_evidence={"codeql": str(p)}))
        assert res_.decision is Decision.FAIL

    def test_corrupt_external_report_is_error(self, repo, gate, tmp_path):
        self._repo(repo)
        p = tmp_path / "codeql.sarif"
        p.write_text("{")
        assert _gate_ok(gate(external_evidence={"codeql": str(p)})).decision is Decision.ERROR


class TestChangedCoverage:
    def test_low_changed_line_coverage_requires_review(self, repo, gate):
        cov = (
            "import os; os.makedirs('out', exist_ok=True); open('out/cov.lcov','w').write("
            "'SF:app/m.py\\nDA:1,1\\nDA:2,1\\nDA:3,0\\nDA:4,0\\nend_of_record\\n')"
        )
        pol = f"""
version: 1
required_checks:
  - name: cov
    command: [{PY!r}, -c, {cov!r}]
    report: {{format: lcov, path: out/cov.lcov}}
    min_changed_coverage: 0.9
"""
        repo.commit({"review-gate.yaml": pol, "app/m.py": "a = 1\nb = 2\n"})
        repo.git("checkout", "-q", "-b", "agent")
        repo.commit({"app/m.py": "a = 1\nb = 2\nc = 3\nd = 4\n"})
        res = _gate_ok(gate())
        assert res.decision is Decision.REVIEW_REQUIRED
        assert "changed_code_coverage_low" in codes(res)


def test_report_path_must_stay_inside_workspace():
    from aicrg.policy.contract import PolicyError, parse_contract

    for bad in ("../x.sarif", "/abs.sarif", ".git/x"):
        with pytest.raises(PolicyError):
            parse_contract(
                f"version: 1\nrequired_checks:\n  - name: s\n    command: x\n"
                f"    report: {{format: sarif, path: {bad}}}\n"
            )
    assert Path  # keep import used
