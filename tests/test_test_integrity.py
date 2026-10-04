import ast

import pytest

from aicrg.model import Severity
from aicrg.testsafety.assertions import expr_strength, extract_assertions
from tests.conftest import POLICY_OK, codes


def strength(src: str) -> int:
    node = ast.parse(src).body[0]
    assert isinstance(node, ast.Assert)
    return expr_strength(node.test)[0]


@pytest.mark.parametrize(
    ("src", "expected"),
    [
        ("assert True", 0),
        ("assert x or True", 0),
        ("assert x == x", 0),
        ("assert 1 == 1", 0),
        ("assert r.status != 500", 1),
        ("assert r is not None", 1),
        ("assert r", 1),
        ("assert r.status >= 400", 2),
        ("assert 'a' in r.body", 2),
        ("assert isinstance(r, Resp)", 2),
        ("assert r.status == 401", 3),
        ("assert 401 == r.status", 3),
        ("assert r is None", 3),
        ("assert r.status == 401 or r.status == 403", 1),
        ("assert r.status == 401 and r.body == {}", 3),
    ],
)
def test_assertion_strength(src, expected):
    assert strength(src) == expected


def test_extracts_method_and_raises_assertions():
    tree = ast.parse(
        "def test_x(self):\n"
        "    self.assertEqual(a, 1)\n"
        "    self.assertTrue(True)\n"
        "    with pytest.raises(ValueError, match='bad'):\n"
        "        f()\n"
    )
    found = extract_assertions(tree.body[0])
    kinds = sorted((a.kind, a.strength) for a in found)
    assert kinds == [("method", 0), ("method", 3), ("raises", 3)]


BASE_TEST = """
import pytest

def handle(h):
    return 401 if not h else 200

def test_unauthenticated_gets_401():
    status = handle({})
    assert status == 401

def test_ok():
    assert handle({"a": 1}) == 200

@pytest.mark.parametrize("h", [{}, None, ""])
def test_rejects_empty_credentials(h):
    assert handle(h) == 401

def test_bad_input_raises():
    with pytest.raises(ValueError, match="bad"):
        raise ValueError("bad")
"""


def _patch(repo, gate, new_test: str):
    repo.commit({"review-gate.yaml": POLICY_OK, "tests/test_auth.py": BASE_TEST})
    repo.git("checkout", "-q", "-b", "agent")
    repo.commit({"tests/test_auth.py": new_test})
    return gate()


def test_weakened_security_assertion_blocks(repo, gate):
    res = _patch(repo, gate, BASE_TEST.replace("assert status == 401", "assert status != 500"))
    f = next(f for f in res.findings if f.code == "assertion_weakened")
    assert f.severity is Severity.BLOCK
    assert f.before == "assert status == 401" and f.after == "assert status != 500"
    assert res.decision.value == "FAIL"


def test_removed_assertion_in_security_test_blocks(repo, gate):
    res = _patch(repo, gate, BASE_TEST.replace("    assert status == 401\n", "    pass\n"))
    assert "assertion_removed" in codes(res)
    assert res.decision.value == "FAIL"


def test_deleted_test_function_blocks(repo, gate):
    new = BASE_TEST.replace('def test_ok():\n    assert handle({"a": 1}) == 200\n\n', "")
    res = _patch(repo, gate, new)
    assert "test_function_removed" in codes(res)
    assert res.decision.value == "FAIL"


def test_unconditional_skip_blocks(repo, gate):
    new = BASE_TEST.replace(
        "def test_unauthenticated_gets_401", "@pytest.mark.skip\ndef test_unauthenticated_gets_401"
    )
    res = _patch(repo, gate, new)
    assert "unconditional_skip_added" in codes(res)


def test_skipif_true_is_unconditional(repo, gate):
    new = BASE_TEST.replace("def test_ok", "@pytest.mark.skipif(True, reason='x')\ndef test_ok")
    assert "unconditional_skip_added" in codes(_patch(repo, gate, new))


def test_body_skip_call_is_unconditional(repo, gate):
    new = BASE_TEST.replace(
        "    status = handle({})", "    pytest.skip('later')\n    status = handle({})"
    )
    assert "unconditional_skip_added" in codes(_patch(repo, gate, new))


def test_broadened_exception_blocks(repo, gate):
    new = BASE_TEST.replace('pytest.raises(ValueError, match="bad")', "pytest.raises(Exception)")
    assert "expected_exception_broadened" in codes(_patch(repo, gate, new))


def test_parametrize_shrink(repo, gate):
    new = BASE_TEST.replace('[{}, None, ""]', "[{}]")
    res = _patch(repo, gate, new)
    f = next(f for f in res.findings if f.code == "parametrize_cases_reduced")
    assert f.severity is Severity.BLOCK  # security-named test


def test_strengthening_and_adding_tests_passes(repo, gate):
    new = (
        BASE_TEST.replace(
            "    assert status == 401\n",
            "    assert status == 401\n    assert isinstance(status, int)\n",
        )
        + "\n\ndef test_more():\n    assert handle({}) == 401\n"
    )
    res = _patch(repo, gate, new)
    assert codes(res) == set()
    assert res.decision.value == "PASS"


def test_moved_test_file_is_not_deletion(repo, gate):
    repo.commit({"review-gate.yaml": POLICY_OK, "tests/test_auth.py": BASE_TEST})
    repo.git("checkout", "-q", "-b", "agent")
    repo.git("mv", "tests/test_auth.py", "tests/test_security_auth.py")
    repo.commit()
    res = gate()
    assert "test_file_deleted" not in codes(res)
    assert res.decision.value == "PASS"


def test_test_file_deleted(repo, gate):
    repo.commit({"review-gate.yaml": POLICY_OK, "tests/test_auth.py": BASE_TEST})
    repo.git("checkout", "-q", "-b", "agent")
    repo.commit(delete=("tests/test_auth.py",))
    res = gate()
    assert "test_file_deleted" in codes(res)
    assert res.decision.value == "FAIL"


def test_test_deletion_is_review_when_not_forbidden(repo, gate):
    policy = "version: 1\nforbidden_changes: []\n"
    repo.commit({"review-gate.yaml": policy, "tests/test_auth.py": BASE_TEST})
    repo.git("checkout", "-q", "-b", "agent")
    repo.commit(delete=("tests/test_auth.py",))
    res = gate()
    assert res.decision.value == "REVIEW_REQUIRED"  # never silently PASS


def test_golden_file_edit(repo, gate):
    repo.commit({"review-gate.yaml": POLICY_OK, "tests/golden/out.json": '{"a": 1}\n'})
    repo.git("checkout", "-q", "-b", "agent")
    repo.commit({"tests/golden/out.json": '{"a": 2}\n'})
    assert "golden_data_modified" in codes(gate())


def test_pytest_addopts_ignore(repo, gate):
    base = '[tool.pytest.ini_options]\naddopts = "-q"\n'
    repo.commit({"review-gate.yaml": POLICY_OK, "pyproject.toml": base})
    repo.git("checkout", "-q", "-b", "agent")
    repo.commit({"pyproject.toml": base.replace('"-q"', '"-q --deselect tests/test_a.py::t"')})
    assert "test_config_excludes_tests" in codes(gate())


def test_unparseable_test_file_needs_review(repo, gate):
    res = _patch(repo, gate, BASE_TEST + "\ndef broken(:\n")
    assert "unparseable_python" in codes(res)
    assert res.decision.value != "PASS"


def test_assertion_replaced_by_unrelated_one_needs_review(repo, gate):
    new = BASE_TEST.replace("    assert status == 401\n", "    assert handle({'x': 1}) == 200\n")
    res = _patch(repo, gate, new)
    assert "assertion_subject_dropped" in codes(res)
    assert res.decision.value != "PASS"


def test_test_that_rewrites_its_golden_file(repo, gate):
    new = BASE_TEST + (
        "\n\ndef test_report(tmp_path):\n"
        "    out = render()\n"
        "    GOLDEN_PATH.write_text(out)\n"
        "    assert out == GOLDEN_PATH.read_text()\n"
    )
    assert "golden_regenerated_by_test" in codes(_patch(repo, gate, new))
