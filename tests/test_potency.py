"""Patch-aware test potency (changed-code mutation)."""

import sys

from aicrg.model import Decision, Severity
from aicrg.potency.mutators import generate, sample
from tests.conftest import codes

PY = sys.executable

BASE_CODE = """
def discount(total, is_member):
    return 0
"""

# The patch adds real logic on several lines.
NEW_CODE = """
def discount(total, is_member):
    if is_member and total >= 100:
        return total // 10
    return 0
"""

STRONG_TEST = """
from app.price import discount

def test_member_over_threshold():
    assert discount(200, True) == 20
    # Without a non-multiple of 10, `total // 10` -> `total / 10` survives (20.0 == 20).
    assert discount(155, True) == 15

def test_member_at_threshold():
    assert discount(100, True) == 10

def test_member_under_threshold():
    assert discount(99, True) == 0

def test_non_member():
    assert discount(200, False) == 0

def test_zero():
    assert discount(1, False) == 0
"""

# Executes every changed line (100% line coverage) but constrains almost nothing.
WEAK_TEST = """
from app.price import discount

def test_runs():
    assert discount(200, True) is not None
    assert discount(5, False) is not None

def test_zero():
    assert discount(1, False) == 0
"""


def _policy(extra: str = "") -> str:
    return f"""
version: 1
test_potency:
  command: [{PY!r}, -m, pytest, -q, -x, -p, no:cacheprovider, tests]
  paths: [app/**]
  mutant_timeout_seconds: 60
{extra}"""


def _repo(repo, policy=None):
    repo.commit(
        {
            "review-gate.yaml": policy or _policy(),
            "app/__init__.py": "",
            "app/price.py": BASE_CODE,
            "tests/__init__.py": "",
            "tests/test_price.py": "from app.price import discount\n\ndef test_zero():\n    assert discount(1, False) == 0\n",
        }
    )
    repo.git("checkout", "-q", "-b", "agent")


class TestGenerator:
    def test_only_changed_lines_are_mutated(self):
        src = NEW_CODE.encode()
        g = generate("app/price.py", src, {3})
        assert g.mutants and {m.line for m in g.mutants} == {3}

    def test_edits_are_local_and_compile(self):
        src = NEW_CODE.encode()
        g = generate("app/price.py", src, {3, 4, 5})
        for m in g.mutants:
            compile(m.source, "x", "exec")
            changed = [
                i
                for i, (a, b) in enumerate(
                    zip(src.splitlines(), m.source.splitlines(), strict=False)
                )
                if a != b
            ]
            assert changed == [m.line - 1]

    def test_equivalent_mutants_are_recognised_not_run(self):
        g = generate("m.py", b"def f():\n    return 1 if True else 1\n", {2})
        assert [m.operator for m in g.equivalent] == ["constant_number"]

    def test_pragma_lines_are_skipped_and_reported(self):
        src = b"def f(x):\n    return x > 1  # pragma: no mutate\n"
        g = generate("m.py", src, {2})
        assert g.mutants == [] and g.suppressed_lines == [2]

    def test_docstrings_annotations_fstrings_are_not_mutated(self):
        src = b'def f(x: int = 3) -> "str":\n    """Doc 1."""\n    return f"{x + 1}"\n'
        g = generate("m.py", src, {1, 2, 3})
        assert {m.operator for m in g.mutants} <= {"constant_number", "return_none"}
        assert not any(m.before == '"""Doc 1."""' for m in g.mutants)

    def test_sampling_is_reproducible_from_its_recorded_seed(self):
        g = generate("app/price.py", NEW_CODE.encode(), {3, 4, 5})
        assert sample(g.mutants, 3, 1234) == sample(g.mutants, 3, 1234)
        assert len(sample(g.mutants, 3, 1234)) == 3
        seen = {tuple(m.id for m in sample(g.mutants, 3, s)) for s in range(20)}
        assert len(seen) > 1  # not a fixed, predictable subset


class TestPotencyGate:
    def test_strong_tests_kill_every_mutant(self, repo, gate):
        _repo(repo)
        repo.commit({"app/price.py": NEW_CODE, "tests/test_price.py": STRONG_TEST})
        res = gate()
        tp = res.receipt["test_potency"]
        assert tp["status"] == "COMPLETE", tp
        assert (
            tp["survived"] == 0
            and tp["killed"] + tp["killed_by_timeout"] == tp["relevant_mutants"] > 0
        )
        assert res.decision is Decision.PASS, res.receipt["reasons"]
        assert res.sections["Test potency"] == "PASS"

    def test_covered_but_weakly_asserted_code_needs_review(self, repo, gate):
        _repo(repo)
        repo.commit({"app/price.py": NEW_CODE, "tests/test_price.py": WEAK_TEST})
        res = gate()
        tp = res.receipt["test_potency"]
        assert tp["status"] == "SURVIVORS" and tp["survived"] > 0
        assert res.decision is Decision.REVIEW_REQUIRED
        f = next(f for f in res.findings if f.code == "test_potency_survivor")
        assert f.severity is Severity.REVIEW and f.file == "app/price.py" and f.before and f.after

    def test_on_survivor_fail_blocks(self, repo, gate):
        _repo(repo, _policy("  on_survivor: fail\n"))
        repo.commit({"app/price.py": NEW_CODE, "tests/test_price.py": WEAK_TEST})
        assert gate().decision is Decision.FAIL

    def test_failing_baseline_is_never_pass(self, repo, gate):
        _repo(repo)
        broken = STRONG_TEST.replace("== 20", "== 21")
        repo.commit({"app/price.py": NEW_CODE, "tests/test_price.py": broken})
        res = gate()
        assert res.receipt["test_potency"]["status"] == "ERROR"
        assert "test_potency_unavailable" in codes(res)
        assert res.decision is Decision.REVIEW_REQUIRED

    def test_on_error_error_makes_gate_error(self, repo, gate):
        _repo(repo, _policy("  on_error: error\n"))
        broken = STRONG_TEST.replace("== 20", "== 21")
        repo.commit({"app/price.py": NEW_CODE, "tests/test_price.py": broken})
        assert gate().decision is Decision.ERROR

    def test_mutation_tool_unavailable_is_never_pass(self, repo, gate):
        pol = _policy().replace(f"[{PY!r}, -m, pytest", "[no-such-test-runner-xyz, -m, pytest")
        _repo(repo, pol)
        repo.commit({"app/price.py": NEW_CODE, "tests/test_price.py": STRONG_TEST})
        res = gate()
        assert res.receipt["test_potency"]["status"] == "ERROR"
        assert res.decision is Decision.REVIEW_REQUIRED

    def test_total_budget_timeout_is_never_pass(self, repo, gate):
        slow = STRONG_TEST + "\nimport time\n\ndef test_slow():\n    time.sleep(1.2)\n"
        _repo(repo, _policy("  total_timeout_seconds: 1\n"))
        repo.commit({"app/price.py": NEW_CODE, "tests/test_price.py": slow})
        res = gate()
        tp = res.receipt["test_potency"]
        assert tp["status"] == "TIMEOUT" and tp["not_run"] > 0
        assert res.decision is Decision.REVIEW_REQUIRED

    def test_per_mutant_timeout_counts_as_killed(self, repo, gate):
        loop_code = "def spin(n):\n    i = 0\n    while i < n:\n        i += 1\n    return i\n"
        test = "from app.price import spin\n\ndef test_spin():\n    assert spin(3) == 3\n\ndef test_zero():\n    pass\n"
        _repo(repo, _policy().replace("mutant_timeout_seconds: 60", "mutant_timeout_seconds: 3"))
        repo.commit({"app/price.py": loop_code, "tests/test_price.py": test})
        res = gate()
        tp = res.receipt["test_potency"]
        assert tp["killed_by_timeout"] >= 1, tp
        assert tp["status"] in ("COMPLETE", "SURVIVORS")

    def test_no_production_change_is_no_mutants(self, repo, gate):
        _repo(repo)
        repo.commit({"README.md": "docs\n"})
        res = gate()
        assert res.receipt["test_potency"]["status"] == "NO_MUTANTS"
        assert res.decision is Decision.PASS

    def test_added_pragma_is_reported(self, repo, gate):
        _repo(repo)
        code = NEW_CODE.replace("total >= 100:", "total >= 100:  # pragma: no mutate")
        repo.commit({"app/price.py": code, "tests/test_price.py": STRONG_TEST})
        res = gate()
        assert "test_potency_suppressed" in codes(res)
        assert res.decision is Decision.REVIEW_REQUIRED

    def test_no_run_with_potency_contract_is_error(self, repo, gate):
        _repo(repo)
        repo.commit({"app/price.py": NEW_CODE, "tests/test_price.py": STRONG_TEST})
        assert gate(run_potency=False).decision is Decision.ERROR
