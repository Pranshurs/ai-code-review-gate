# Test integrity

Coding agents asked to "make the tests pass" sometimes make the tests prove
less instead of making the code correct. AICRG's test-integrity analysis asks one
question: **did this patch make the tests weaker than they were at base?**

It never asks whether the tests are good in absolute terms.

## How it works (Python)

1. For every changed test file (`tests/**`, `test_*.py`, `*_test.py`,
   `conftest.py`), parse base and head with `ast`.
2. Collect test functions by qualified name (`TestAuth.test_x`, `test_y`), with
   their assertions, skip/xfail markers (function, class and module `pytestmark`)
   and `parametrize` cases.
3. Compare each test between base and head:
   * assertions as **multisets** of normalised source, so reordering is not a change;
   * removed and added assertions **paired by subject** (the thing asserted on), so
     `assert r.status == 401` → `assert r.status != 500` is one *weakened*
     assertion, not "one removed, one added";
   * each assertion scored by **strength** (below).
4. Tests that disappeared are matched against tests that appeared anywhere in the
   patch. Identical assertions mean "moved/renamed" (advisory), otherwise "removed".

### Assertion strength

| strength | forms |
|---|---|
| 0 vacuous | `assert True`, `assert x or True`, `assert x == x`, `assertTrue(True)`, two constants |
| 1 weak | truthiness, `!=`, `is not`, `assertTrue(x)`, `assertIsNotNone`, `a or b` |
| 2 bounded | `<`, `>=`, `in`, `isinstance`, `assertIn`, `assertRegex`, `assert_called` |
| 3 exact | `==`, `is`, `assertEqual`, `assertIsNone`, `pytest.raises(...)`, `assert_called_once_with` |

## Signals

| code | example | default severity |
|---|---|---|
| `assertion_weakened` | `== 401` → `!= 500` | BLOCK (`forbid_assertion_weakening`) |
| `vacuous_assertion_added` | `assert x == 1` → `assert x == 1 or True` | BLOCK |
| `expected_exception_broadened` | `raises(InvalidToken)` → `raises(Exception)`; `match=` dropped | BLOCK |
| `unreachable_assertions` | `return` inserted before the assertions | BLOCK |
| `assertion_swallowed` | assertions wrapped in `try/except AssertionError: pass` | BLOCK |
| `assertion_removed` | assertions deleted from a test that still exists | BLOCK in security tests, else REVIEW |
| `assertion_subject_dropped` | `assert not marker.exists()` → `assert p.exists()` | REVIEW |
| `expected_value_changed` | `== "0.13"` → `== "0.12"` | REVIEW |
| `test_function_removed` / `test_file_deleted` | failing security test deleted | BLOCK (`test_deletion`) |
| `test_function_renamed` | moved with identical assertions | advisory |
| `unconditional_skip_added` | `@pytest.mark.skip`, `skipif(True)`, `pytest.skip()` in the body | BLOCK |
| `xfail_added` | `@pytest.mark.xfail` | REVIEW |
| `parametrize_cases_reduced` | 5 malformed-header cases → 3 | BLOCK in security tests, else REVIEW |
| `golden_data_modified` | `tests/golden/*.json` edited | BLOCK (`golden_data_modification`) |
| `golden_regenerated_by_test` | the test writes the expected file it compares against | BLOCK |
| `collection_hook_modified` | `pytest_collection_modifyitems`, `collect_ignore` changed | REVIEW |
| `test_config_excludes_tests` | `addopts = --ignore=...`, `testpaths` narrowed | BLOCK (`ci_test_bypass`) |
| `coverage_threshold_lowered` | `fail_under 90 → 40` | BLOCK |
| `checker_config_loosened` | mypy `strict` off, ruff rules deselected or ignored | BLOCK |
| `checker_suppression_added` | `# mypy: ignore-errors`, `# ruff: noqa` at file top | BLOCK |
| `ci_*` | `pytest \|\| true`, `--exit-zero`, removed test step, `if: false` | BLOCK |
| `unparseable_python` | head test file does not parse | REVIEW (analysis incomplete) |

A **security test** is one whose file, name or assertions match
`auth|login|permission|forbidden|unauthori[sz]ed|admin|csrf|token|tls|verify|401|403|role|tenant|...`.
That is a name heuristic. A security test called `test_case_7` is not recognised.

## What it does not detect (known false negatives)

These are real gaps. Several appear as misses in the held-out results:

* **Indirection.** Assertions moved into a helper that asserts less, fixtures
  that change behaviour, mocks that make the code under test trivial,
  `conftest.py` hooks other than the named collection hooks.
* **Same-shape semantic changes.** Changing the *input* so the assertion becomes
  trivially true, swapping one exact assertion for another exact but wrong one on
  a new subject (reported only as REVIEW when the old subject disappears).
* **Timeouts and slow paths.** Reduced `@pytest.mark.timeout` or
  smaller loop bounds in tests are not modelled.
* **Narrow suppression of real errors**, e.g. `contextlib.suppress(OSError)`
  around a write. Only broad handlers (`Exception`, `BaseException`, bare) are
  reported, to keep false positives manageable.
* **Non-Python test suites.** Only workflow/config signals apply.

## Known false positives

* Legitimate test refactors that drop an assertion: REVIEW_REQUIRED, by design.
* Deleting obsolete tests along with the feature they test: BLOCK under the
  default contract. Remove `test_deletion` from `forbidden_changes` to make it
  REVIEW instead.
* Renaming the variable an assertion is about inside a security test can report
  `assertion_subject_dropped` (REVIEW).

## Prior art

`tampercheck` and `tamperguard` (PyPI) flag similar patterns with regular
expressions over unified diffs, across more languages. AICRG's difference is the
per-test base/head pairing with strength scoring, and that the results are one
input to an evidence-bound decision. See docs/ECOSYSTEM.md.
