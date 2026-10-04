"""Regression tests for the cold security review findings (docs/SECURITY_REVIEW.md).

Each test reproduces the reviewer's attack in miniature and asserts the fixed
behaviour. IDs match the review report.
"""

import json
import sys
import textwrap
import time
from pathlib import Path

import pytest

from aicrg.doctor import github_checks, static_checks
from aicrg.evidence.differential import DiffClass, classify
from aicrg.evidence.executor import ExecRequest, LocalExecutor
from aicrg.evidence.providers import ProviderStatus, ReportError, parse_junit
from aicrg.evidence.trusted import (
    TrustedEvidenceError,
    bundle_from_bytes,
    load_bundle,
    tree_digest,
)
from aicrg.globmatch import match
from aicrg.model import Decision
from aicrg.receipt.receipt import write_receipt
from aicrg.receipt.verify import verify_receipt
from tests.conftest import codes
from tests.test_execution_boundary import DOCKER, IMAGE

PY = sys.executable


# ----------------------------------------------------------------------------- F12


def test_f12_globs_match_paths_with_newlines():
    assert match("trusted_tests/test_00\nx.py", "trusted_tests/**")
    assert match("src/auth/policy\n.py", "src/auth/**")
    assert not match("a.py\n", "a.py\nb")  # fullmatch: no `$`-before-newline slack
    assert not match("x.py\n", "*.pyc")


def test_f12_control_character_paths_block(repo, gate):
    repo.commit(
        {"review-gate.yaml": "version: 1\nprotected_paths: [src/auth/**]\n", "a.py": "x=1\n"}
    )
    repo.git("checkout", "-q", "-b", "agent")
    repo.commit({"src/auth/policy\n.py": "ALLOW = True\n"})
    res = gate()
    assert res.decision is Decision.FAIL
    assert {"unsafe_path_name", "protected_path_modified"} <= codes(res)


# ----------------------------------------------------------------------------- F2


def test_f2_bundle_digest_is_injective(tmp_path):
    a, b = b"def test_a():\n    pass\n", b"def test_b():\n    assert False\n"
    import hashlib

    legit = {"test_a.py": (a, False), "test_b.py": (b, False)}
    pin = tree_digest(legit)
    forged_name = f"test_a.py\n100644 {hashlib.sha256(b).hexdigest()} test_b.py"
    # v1 would have produced the same manifest bytes; v2 must not.
    assert tree_digest({forged_name: (a, False)}) != pin
    evil = tmp_path / "evil.tar"
    evil.write_bytes(bundle_from_bytes({forged_name: a}))
    with pytest.raises(TrustedEvidenceError):
        load_bundle(evil, pin)


# ----------------------------------------------------------------------------- F13 / F3

TRUSTED_POLICY = f"""
version: 1
trusted_evidence:
  - name: contract
    source: base
    paths: [trusted_tests/**]
    command: [{PY!r}, -m, pytest, -q, -p, no:cacheprovider, --confcutdir, trusted_tests, trusted_tests]
"""
GOOD = "def ok(x):\n    return x > 0\n"
BROKEN = "def ok(x):\n    return True\n"
WEAK_TRUSTED = "from impl import ok\n\ndef test_ok():\n    assert ok(1)\n"
STRONG_TRUSTED = WEAK_TRUSTED + "\ndef test_negative():\n    assert not ok(-1)\n"


def test_f13_trusted_content_comes_from_base_tip_not_stale_merge_base(repo, gate):
    repo.commit(
        {
            "review-gate.yaml": TRUSTED_POLICY,
            "impl.py": GOOD,
            "trusted_tests/test_c.py": WEAK_TRUSTED,
        }
    )
    repo.git("checkout", "-q", "-b", "agent")  # branch cut from the OLD base
    repo.commit({"impl.py": BROKEN})
    repo.git("checkout", "-q", "main")
    repo.commit({"trusted_tests/test_c.py": STRONG_TRUSTED})  # base strengthens its contract
    repo.git("checkout", "-q", "agent")
    res = gate()
    assert res.decision is Decision.FAIL
    assert "trusted_evidence_failed" in codes(res)


TAMPER_IMPL = textwrap.dedent(
    """
    import pathlib
    p = pathlib.Path(__file__).parent / "trusted_tests" / "test_z.py"
    try:
        p.write_text("def test_z():\\n    pass\\n")
    except OSError:
        pass

    def ok(x):
        return True
    """
)


def _tamper_repo(repo, policy):
    repo.commit(
        {
            "review-gate.yaml": policy,
            "impl.py": GOOD,
            "trusted_tests/test_a.py": "import impl\n\ndef test_a():\n    assert impl.ok(1)\n",
            "trusted_tests/test_z.py": "from impl import ok\n\ndef test_z():\n    assert not ok(-1)\n",
        }
    )
    repo.git("checkout", "-q", "-b", "agent")
    repo.commit({"impl.py": TAMPER_IMPL})


def test_f3_trusted_files_rewritten_during_run_is_never_pass_local(repo, gate):
    _tamper_repo(repo, TRUSTED_POLICY)
    res = gate()
    assert res.decision in (Decision.ERROR, Decision.FAIL)
    assert res.decision is not Decision.PASS


TAMPER_IMPL_DETERMINED = textwrap.dedent(
    """
    import os, pathlib, stat
    p = pathlib.Path(__file__).parent / "trusted_tests" / "test_z.py"
    # Locally, read-only trusted files are best effort: their owner (the
    # candidate's own user) can make them writable again.
    os.chmod(p.parent, stat.S_IRWXU)
    os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)
    p.write_text("def test_z():\\n    pass\\n")

    def ok(x):
        return True
    """
)


def test_f3_owner_restoring_write_permission_is_detected_local(repo, gate):
    """The local executor cannot *prevent* a same-user rewrite (a-w is undone by
    chmod); post-run verification must *detect* it. Independent of running as
    root (where a-w never blocks) or not (where the naive tamper is blocked and
    the real trusted test fails instead): here the rewrite always succeeds, so
    only verification stands between it and PASS."""
    _tamper_repo(repo, TRUSTED_POLICY)
    repo.commit({"impl.py": TAMPER_IMPL_DETERMINED})
    res = gate()
    assert res.decision is Decision.ERROR
    run = next(c for c in res.checks if c.name == "contract")
    assert "modified during its own run" in str(run.to_json()), run.to_json()


@pytest.mark.skipif(not DOCKER, reason="docker unavailable")
def test_f3_trusted_paths_are_read_only_in_container(repo, gate):
    pol = (
        f"version: 1\nexecution:\n  executor: container\n  container:\n    image: {IMAGE}\n"
        "trusted_evidence:\n  - name: contract\n    source: base\n    paths: [trusted_tests/**]\n"
        "    command: [python, -m, unittest, discover, -s, trusted_tests, -t, .]\n"
    )
    repo.commit(
        {
            "review-gate.yaml": pol,
            "impl.py": GOOD,
            "trusted_tests/__init__.py": "",
            "trusted_tests/test_a.py": "import unittest, impl\n\nclass A(unittest.TestCase):\n    def test_a(self):\n        self.assertTrue(impl.ok(1))\n",
            "trusted_tests/test_z.py": "import unittest\nfrom impl import ok\n\nclass Z(unittest.TestCase):\n    def test_z(self):\n        self.assertFalse(ok(-1))\n",
        }
    )
    repo.git("checkout", "-q", "-b", "agent")
    repo.commit({"impl.py": TAMPER_IMPL})
    res = gate()
    assert res.decision is Decision.FAIL  # the rewrite is refused; the real trusted test fails
    assert "trusted_evidence_failed" in codes(res)


# ----------------------------------------------------------------------------- F4


def test_f4_coverage_tool_exit_1_is_not_pass(repo, gate):
    script = (
        "import pathlib, sys\npathlib.Path('out').mkdir(exist_ok=True)\n"
        "pathlib.Path('out/c.lcov').write_text('SF:a.py\\nDA:1,1\\nend_of_record\\n')\n"
        "sys.exit(1)\n"
    )
    pol = (
        f"version: 1\nrequired_checks:\n  - name: cov\n    command: [{PY!r}, run.py]\n"
        "    report: {format: lcov, path: out/c.lcov}\n"
    )
    repo.commit({"review-gate.yaml": pol, "run.py": script, "a.py": "x = 1\n"})
    repo.git("checkout", "-q", "-b", "agent")
    repo.commit({"a.py": "x = 2\n"})
    res = gate()
    assert res.decision is Decision.FAIL
    assert res.checks[0].provider_status == "FINDINGS"


# ----------------------------------------------------------------------------- F5


def test_f5_duplicate_identical_finding_is_a_new_regression():
    from collections import Counter

    base, head = Counter({"R|a.py|msg": 1}), Counter({"R|a.py|msg": 2})
    assert classify(ProviderStatus.FINDINGS, ProviderStatus.FINDINGS, base, head) is (
        DiffClass.NEW_REGRESSION
    )
    assert classify(ProviderStatus.FINDINGS, ProviderStatus.FINDINGS, head, base) is (
        DiffClass.PRE_EXISTING_FAILURE
    )


# ----------------------------------------------------------------------------- F6

POT_POLICY = f"""
version: 1
test_potency:
  command: [{PY!r}, -m, pytest, -q, -x, -p, no:cacheprovider, tests]
  mutant_timeout_seconds: 60
"""


def test_f6a_self_hash_test_cannot_fake_potency(repo, gate):
    repo.commit(
        {
            "review-gate.yaml": POT_POLICY,
            "pkg/__init__.py": "",
            "pkg/mod.py": "def is_adult(age):\n    return False\n",
            "tests/__init__.py": "",
            "tests/test_mod.py": "def test_zero():\n    pass\n",
        }
    )
    repo.git("checkout", "-q", "-b", "agent")
    code = "def is_adult(age):\n    return age >= 18\n"
    import hashlib

    digest = hashlib.sha256(code.encode()).hexdigest()
    test = (
        "import hashlib, pathlib\nfrom pkg.mod import is_adult\n\ndef test_zero():\n    pass\n\n"
        "def test_adult():\n    assert is_adult(30)\n\ndef test_source_pinned():\n"
        "    src = pathlib.Path('pkg/mod.py').read_bytes()\n"
        f"    assert hashlib.sha256(src).hexdigest() == {digest!r}\n"
    )
    repo.commit({"pkg/mod.py": code, "tests/test_mod.py": test})
    res = gate()
    tp = res.receipt["test_potency"]
    assert tp["status"] == "ERROR" and "control mutant" in tp["reason"]
    assert res.decision is Decision.REVIEW_REQUIRED


def test_f6b_truncated_sample_is_not_complete(repo, gate):
    pol = POT_POLICY + "  max_mutants: 2\n"
    repo.commit(
        {
            "review-gate.yaml": pol,
            "pkg/__init__.py": "",
            "pkg/mod.py": "X = 0\n",
            "tests/__init__.py": "",
            "tests/test_mod.py": "def test_zero():\n    pass\n",
        }
    )
    repo.git("checkout", "-q", "-b", "agent")
    code = "def f(a, b):\n    if a > 1 and b < 2:\n        return a + b\n    return a - b\n"
    test = (
        "from pkg.mod import f\n\ndef test_zero():\n    pass\n\n"
        "def test_f():\n    assert f(5, 0) == 5\n    assert f(0, 5) == -5\n    assert f(2, 1) == 3\n"
        "    assert f(1, 1) == 0\n    assert f(2, 2) == 0\n"
    )
    repo.commit({"pkg/mod.py": code, "tests/test_mod.py": test})
    res = gate()
    tp = res.receipt["test_potency"]
    assert tp["sampled_from"] > tp["relevant_mutants"] == 2
    assert tp["sample_seed"] is not None
    assert tp["status"] == "SAMPLED"  # every mutant is killed when all are run
    assert res.decision is Decision.REVIEW_REQUIRED


def test_f16_unparseable_target_is_error_not_no_mutants(repo, gate):
    repo.commit(
        {
            "review-gate.yaml": POT_POLICY,
            "pkg/__init__.py": "",
            "pkg/mod.py": "X = 0\n",
            "tests/__init__.py": "",
            "tests/test_mod.py": "def test_zero():\n    pass\n",
        }
    )
    repo.git("checkout", "-q", "-b", "agent")
    repo.commit({"pkg/mod.py": "def f(:\n    pass\n"})
    tp = gate().receipt["test_potency"]
    assert tp["status"] == "ERROR" and "cannot parse" in tp["reason"]


# ----------------------------------------------------------------------------- F7

DANGER = "import subprocess\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n"


@pytest.mark.parametrize(
    ("path", "importer"),
    [
        ("app/runner_test.py", "from app.runner_test import run\n"),
        ("app/test_runner.py", "from app import test_runner\n"),
        ("app/test/runner.py", "from .test.runner import run\n"),
    ],
)
def test_f7_test_named_module_imported_by_production_is_analysed(repo, gate, path, importer):
    repo.commit(
        {"review-gate.yaml": "version: 1\n", "app/__init__.py": "", "app/main.py": "x = 1\n"}
    )
    repo.git("checkout", "-q", "-b", "agent")
    repo.commit({path: DANGER, "app/main.py": importer + "x = 1\n"})
    res = gate()
    assert "shell_injection_risk" in codes(res) or "shell_execution_added" in codes(res)
    assert res.decision is not Decision.PASS


def test_f7_real_test_files_are_still_test_files(repo, gate):
    repo.commit(
        {"review-gate.yaml": "version: 1\n", "app/__init__.py": "", "app/main.py": "x = 1\n"}
    )
    repo.git("checkout", "-q", "-b", "agent")
    repo.commit({"tests/test_runner.py": DANGER})
    assert "shell_injection_risk" not in codes(gate())


# ----------------------------------------------------------------------------- F8


def _wf(tmp_path: Path, step: str, extra_job: str = "") -> Path:
    root = tmp_path / "r"
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / ".github" / "workflows" / "g.yml").write_text(
        "on: pull_request\npermissions:\n  contents: read\njobs:\n  gate:\n"
        f"    runs-on: ubuntu-latest\n{extra_job}    steps:\n{step}"
    )
    return root


@pytest.mark.parametrize(
    "step",
    [
        "      - run: aicrg check --base B | tee out.txt\n",
        "      - run: aicrg check --base B || echo ignoring\n",
        "      - run: aicrg check --base B\n        continue-on-error: ${{ true }}\n",
    ],
)
def test_f8_doctor_detects_lost_exit_status(tmp_path, step):
    rep = static_checks(_wf(tmp_path, step))
    assert {c.status for c in rep.checks if c.id == "gate-not-masked"} == {"FAIL"}


def test_f8_pipe_with_pipefail_shell_is_fine(tmp_path):
    step = "      - run: aicrg check --base B | tee out.txt\n        shell: bash\n"
    rep = static_checks(_wf(tmp_path, step))
    assert {c.status for c in rep.checks if c.id == "gate-not-masked"} == {"PASS"}


def test_f8_job_write_all_and_echo_fake_gate(tmp_path):
    rep = static_checks(
        _wf(tmp_path, "      - run: aicrg check --base B\n", "    permissions: write-all\n")
    )
    assert {c.status for c in rep.checks if c.id == "gate-permissions"} == {"FAIL"}
    rep = static_checks(_wf(tmp_path / "x", '      - run: echo "aicrg check"\n'))
    assert {c.status for c in rep.checks if c.id == "gate-present"} == {"FAIL"}


def test_f8b_required_check_match_is_exact():
    rules = [
        {
            "type": "required_status_checks",
            "parameters": {"required_status_checks": [{"context": "lint-aggregate"}]},
        }
    ]
    rep = github_checks(
        "o/r", "main", ["gate"], lambda p: (200, rules) if "rules" in p else (404, None)
    )
    assert {c.status for c in rep.checks if c.id == "github-required-check"} == {"FAIL"}


# ----------------------------------------------------------------------------- F9


def test_f9_utf16_xml_with_entities_is_refused():
    doc = '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE t [<!ENTITY n "x">]><testsuite/>'
    with pytest.raises(ReportError):
        parse_junit(doc.encode("utf-16"))
    # The rule is "UTF-8 only", not "no NUL bytes": Latin-1 without a declaration is refused.
    with pytest.raises(ReportError, match="UTF-8"):
        parse_junit(
            '<testsuite name="caf\u00e9"><testcase name="t"/></testsuite>'.encode("latin-1")
        )


# ----------------------------------------------------------------------------- F10


def test_f10_local_timeout_is_bounded_even_if_a_child_escapes(tmp_path):
    code = (
        "import os, subprocess, time\n"
        "subprocess.Popen(['sleep', '30'], start_new_session=True)\n"  # escapes the group, holds stdout
        "time.sleep(30)\n"
    )
    t0 = time.monotonic()
    out = LocalExecutor().run(ExecRequest((PY, "-c", code), tmp_path, {"PATH": "/usr/bin:/bin"}, 2))
    assert out.timed_out
    assert time.monotonic() - t0 < 15


# ----------------------------------------------------------------------------- F11

EXT_POLICY = "version: 1\nexternal_evidence:\n  - name: codeql\n    format: sarif\n"


def _sarif(revision: str | None = None) -> str:
    run: dict[str, object] = {"tool": {"driver": {"name": "x"}}, "results": []}
    if revision:
        run["versionControlProvenance"] = [{"repositoryUri": "u", "revisionId": revision}]
    return json.dumps({"version": "2.1.0", "runs": [run]})


def test_f11_external_report_inside_checkout_is_refused(repo, gate):
    repo.commit({"review-gate.yaml": EXT_POLICY, "a.py": "x = 1\n"})
    repo.git("checkout", "-q", "-b", "agent")
    repo.commit({"a.py": "x = 2\n", "codeql/out.sarif": _sarif()})
    res = gate(external_evidence={"codeql": str(repo.root / "codeql" / "out.sarif")})
    assert res.decision is Decision.ERROR


def test_f11_external_report_for_another_revision_is_refused(repo, gate, tmp_path):
    repo.commit({"review-gate.yaml": EXT_POLICY, "a.py": "x = 1\n"})
    repo.git("checkout", "-q", "-b", "agent")
    head = repo.commit({"a.py": "x = 2\n"})
    other = tmp_path / "other.sarif"
    other.write_text(_sarif("f" * 40))
    assert gate(external_evidence={"codeql": str(other)}).decision is Decision.ERROR
    same = tmp_path / "same.sarif"
    same.write_text(_sarif(head))
    assert gate(external_evidence={"codeql": str(same)}).decision is Decision.PASS


# ----------------------------------------------------------------------------- F1b


def test_f1b_verify_without_base_cannot_vouch_for_contract(repo, gate, tmp_path):
    repo.commit({"review-gate.yaml": "version: 1\n", "a.py": "x = 1\n"})
    repo.git("checkout", "-q", "-b", "agent")
    repo.commit({"a.py": "x = 2\n"})
    path = write_receipt(gate().receipt, tmp_path / "r")
    v = verify_receipt(path, repo.root, require_base=True)
    assert not v.ok and any("BASE NOT CHECKED" in p for p in v.problems)
    assert verify_receipt(path, repo.root, base="main", require_base=True).ok


# ----------------------------------------------------------------------------- re-verification


def _n1_policy() -> str:
    return (
        f"version: 1\nexecution:\n  executor: container\n  container:\n    image: {IMAGE}\n"
        "trusted_evidence:\n  - name: tt\n    source: base\n    paths: ['trusted/**/*.py']\n"
        "    command: [python, -m, unittest, discover, -s, trusted, -p, 'test_*.py']\n"
    )


def _n1_base(repo) -> None:
    repo.commit(
        {
            "review-gate.yaml": _n1_policy(),
            "impl.py": "def add(a, b):\n    return a + b\n",
            "trusted/a/__init__.py": "",
            "trusted/a/test_a.py": "import unittest, impl\n\nclass A(unittest.TestCase):\n    def test_a(self):\n        pass\n",
            "trusted/b/__init__.py": "",
            "trusted/b/test_b.py": "import unittest, impl\n\nclass B(unittest.TestCase):\n    def test_add(self):\n        self.assertEqual(impl.add(1, 2), 3)\n",
            # The property itself: nothing in the workspace is writable during a trusted run.
            "trusted/b/test_ro.py": "import unittest\n\nclass RO(unittest.TestCase):\n    def test_root_is_read_only(self):\n        with self.assertRaises(OSError):\n            open('probe.txt', 'w')\n",
        }
    )
    repo.git("checkout", "-q", "-b", "agent")


@pytest.mark.skipif(not DOCKER, reason="docker unavailable")
def test_n1_trusted_run_sees_a_read_only_workspace(repo, gate):
    _n1_base(repo)
    repo.commit({"impl.py": "def add(a, b):\n    return b + a\n"})
    res = gate()
    assert res.decision is Decision.PASS, res.receipt["reasons"]


@pytest.mark.skipif(not DOCKER, reason="docker unavailable")
def test_n1_no_writable_gap_next_to_trusted_dirs_in_container(repo, gate):
    """Create-then-delete of a test file in a sibling directory must not reach the run."""
    _n1_base(repo)
    attack = textwrap.dedent(
        """
        import atexit, glob, os
        d = os.path.join(os.path.dirname(os.path.abspath(__file__)), "trusted", "c")
        try:
            open(os.path.join(d, "__init__.py"), "w").close()
            open(os.path.join(d, "test_zz.py"), "w").write(
                "import unittest\\n"
                "def _run(self, result=None):\\n"
                "    result.startTest(self); result.addSuccess(self); result.stopTest(self)\\n"
                "unittest.TestCase.run = _run\\n"
            )
            atexit.register(lambda: [os.remove(f) for f in glob.glob(os.path.join(d, "*"))])
        except OSError:
            pass

        def add(a, b):
            return a - b
        """
    )
    repo.commit({"impl.py": attack, "trusted/c/keep.txt": "placeholder\n"})
    res = gate()
    assert res.decision is Decision.FAIL
    assert "trusted_evidence_failed" in codes(res)


def test_n2_ast_or_bytecode_pin_cannot_fake_potency(repo, gate):
    repo.commit(
        {
            "review-gate.yaml": POT_POLICY,
            "pkg/__init__.py": "",
            "pkg/mod.py": "def is_adult(age):\n    return False\n",
            "tests/__init__.py": "",
            "tests/test_mod.py": "def test_zero():\n    pass\n",
        }
    )
    repo.git("checkout", "-q", "-b", "agent")
    code = "def is_adult(age):\n    years = age\n    return years >= 18\n"
    import ast
    import hashlib

    ast_pin = hashlib.sha256(ast.dump(ast.parse(code)).encode()).hexdigest()
    test = (
        "import ast, hashlib, pathlib\nimport pkg.mod as m\n\ndef test_zero():\n    pass\n\n"
        "def test_adult():\n    assert m.is_adult(30)\n\n"
        "def test_shape_pinned():\n"
        "    tree = ast.parse(pathlib.Path('pkg/mod.py').read_text())\n"
        f"    assert hashlib.sha256(ast.dump(tree).encode()).hexdigest() == {ast_pin!r}\n"
    )
    repo.commit({"pkg/mod.py": code, "tests/test_mod.py": test})
    res = gate()
    tp = res.receipt["test_potency"]
    assert tp["status"] == "ERROR" and "control mutant" in tp["reason"]
    assert res.decision is Decision.REVIEW_REQUIRED


@pytest.mark.parametrize(
    "importer",
    [
        "import importlib\nrun = importlib.import_module('app.runner_' + 'test').run\n",
        "run = __import__('app.runner_test', fromlist=['run']).run\n",
    ],
)
def test_n3_dynamically_imported_test_named_module_is_production(repo, gate, importer):
    repo.commit(
        {"review-gate.yaml": "version: 1\n", "app/__init__.py": "", "app/main.py": "x = 1\n"}
    )
    repo.git("checkout", "-q", "-b", "agent")
    repo.commit({"app/runner_test.py": DANGER, "app/main.py": importer})
    assert {"shell_injection_risk", "shell_execution_added"} & codes(gate())


def test_n3_entry_point_names_production_module(repo, gate):
    repo.commit(
        {
            "review-gate.yaml": "version: 1\n",
            "app/__init__.py": "",
            "pyproject.toml": "[project]\nname='x'\n",
        }
    )
    repo.git("checkout", "-q", "-b", "agent")
    repo.commit(
        {
            "app/runner_test.py": DANGER,
            "pyproject.toml": "[project]\nname='x'\n[project.scripts]\nrun = 'app.runner_test:run'\n",
        }
    )
    assert {"shell_injection_risk", "shell_execution_added"} & codes(gate())


@pytest.mark.parametrize(
    ("step", "extra"),
    [
        ("      - run: aicrg check --base B &\n", ""),
        ("      - run: |\n          aicrg check --base B && echo ok\n          true\n", ""),
        (
            "      - run: |\n          aicrg check --base B\n          echo done\n        shell: bash {0}\n",
            "",
        ),
        ("      - run: '! aicrg check --base B'\n", ""),
        ("      - run: aicrg check --base B\n", "    if: github.event_name == 'push'\n"),
    ],
)
def test_n4_doctor_more_masks(tmp_path, step, extra):
    rep = static_checks(_wf(tmp_path, step, extra))
    assert {c.status for c in rep.checks if c.id == "gate-not-masked"} == {"FAIL"}


def test_n4_default_shell_errexit_is_not_a_mask(tmp_path):
    rep = static_checks(
        _wf(tmp_path, "      - run: |\n          aicrg check --base B\n          echo done\n")
    )
    assert {c.status for c in rep.checks if c.id == "gate-not-masked"} == {"PASS"}


def test_n4_gate_workflow_without_pr_trigger_fails(tmp_path):
    root = _wf(tmp_path, "      - run: aicrg check --base B\n")
    wf = root / ".github" / "workflows" / "g.yml"
    wf.write_text(wf.read_text().replace("on: pull_request", "on: workflow_dispatch"))
    rep = static_checks(root)
    assert "FAIL" in {c.status for c in rep.checks if c.id == "gate-trigger"}


def test_n5_require_revision_refuses_unbound_external_report(repo, gate, tmp_path):
    pol = EXT_POLICY + "    require_revision: true\n"
    repo.commit({"review-gate.yaml": pol, "a.py": "x = 1\n"})
    repo.git("checkout", "-q", "-b", "agent")
    head = repo.commit({"a.py": "x = 2\n"})
    unbound = tmp_path / "u.sarif"
    unbound.write_text(_sarif())
    assert gate(external_evidence={"codeql": str(unbound)}).decision is Decision.ERROR
    bound = tmp_path / "b.sarif"
    bound.write_text(_sarif(head))
    assert gate(external_evidence={"codeql": str(bound)}).decision is Decision.PASS


def test_n2_function_bytecode_pin_cannot_fake_potency(repo, gate):
    """A pin on one function's code object ignores module-level changes; the per-function
    control (a dead local) must still change it."""
    repo.commit(
        {
            "review-gate.yaml": POT_POLICY,
            "pkg/__init__.py": "",
            "pkg/mod.py": "def is_adult(age):\n    return False\n",
            "tests/__init__.py": "",
            "tests/test_mod.py": "def test_zero():\n    pass\n",
        }
    )
    repo.git("checkout", "-q", "-b", "agent")
    code = "def is_adult(age):\n    years = age\n    return years >= 18\n"
    ns: dict[str, object] = {}
    exec(compile(code, "pkg/mod.py", "exec"), ns)  # noqa: S102 - computing the pin
    import hashlib

    pin = hashlib.sha256(ns["is_adult"].__code__.co_code).hexdigest()  # type: ignore[attr-defined]
    test = (
        "import hashlib\nimport pkg.mod as m\n\ndef test_zero():\n    pass\n\n"
        "def test_adult():\n    assert m.is_adult(30)\n\n"
        "def test_code_pinned():\n"
        f"    assert hashlib.sha256(m.is_adult.__code__.co_code).hexdigest() == {pin!r}\n"
    )
    repo.commit({"pkg/mod.py": code, "tests/test_mod.py": test})
    tp = gate().receipt["test_potency"]
    assert tp["status"] == "ERROR" and "control mutant control:is_adult" in tp["reason"]
