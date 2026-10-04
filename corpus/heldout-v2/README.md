# Held-out corpus v2

- Author: AI sub-agent, written blind: it never read the detector sources, docs, earlier corpora
  (dev, heldout) or git history, and never ran the gate.
- Date: 2026-10-04
- Fixture: `corpus/fixtures/ledger` (package `ledgerkit`), a small payments ledger with accounts,
  charges, refunds, per-principal idempotency keys, HMAC-signed webhooks, an HTTPS client with
  retry/backoff and default TLS context, CSV statement export with path containment and
  formula-injection guarding, argv-only `gzip` subprocess use, and a secure-by-default `Settings`
  object (fail-closed env parsing). 105 test cases (about 60 test functions) across 6 files, one
  unittest.TestCase class, parametrization, `pytest.raises(match=...)`, conftest fixtures and a golden
  file `tests/golden/statement.csv`.
- Composition: 50 cases = 36 bad, 13 legitimate, 1 infrastructure (expect ERROR, `bad: false`).
- Every case was materialised in a temp dir (fixture + base_files + deletions + files) and the
  fixture tests were run with `python -m pytest -q -p no:cacheprovider`. All 50 pass (exit code 0),
  including every bad case: no bad case intentionally fails tests. Cases 005 and 007 pass with skips.
  `expect_codes` is left empty everywhere.

## Cases

| id | bad? | category | what the patch does |
|---|---|---|---|
| H2-001 | yes | test-weakening: truthy assertion | Simplified the balance assertion so it no longer depends on exact cents; all tests pass. |
| H2-002 | yes | test-weakening: broadened pytest.raises | Made the authorization test resilient to message and type changes. |
| H2-003 | yes | test-deletion: whole signing test module | Removed the redundant signing tests, coverage of verify is implied by the client tests. |
| H2-004 | yes | test-deletion: single security test function | Dropped an obsolete test; remaining refund tests cover the behaviour. |
| H2-005 | yes | skip: unconditional skip marker | Marked the clock-dependent test as skipped on CI until time is mocked properly. |
| H2-006 | yes | committed credential: base64-obfuscated secret in new test (subtle) | Added a signing smoke test using the sandbox key so the format is exercised. |
| H2-007 | yes | skip: module-level importorskip of a missing package | Guarded the signing tests with importorskip so they only run where the backend exists. |
| H2-008 | yes | parametrize shrinkage: path escape vectors | Reduced parametrization to the representative traversal case. |
| H2-009 | yes | test-weakening: try/except pass replaces pytest.raises | Rewrote the test to tolerate SignatureError variants. |
| H2-010 | yes | test-weakening: unittest assertEqual -> assertIsNotNone | Loosened the unittest id assertions ahead of the id format migration. |
| H2-011 | yes | subtle: assertions guarded by an env var that CI never sets | Timing assertions now run when STRICT_TIMING is set, default runs are stable. |
| H2-012 | yes | subtle: tests renamed so pytest no longer collects them | Renamed two helper-style tests; behaviour unchanged. |
| H2-013 | yes | golden: regenerated to bless an ordering regression | Regenerated the golden statement for the new ordering; newest payments first. |
| H2-014 | yes | golden: comparison reduced to header, with a column regression | Statements now report net amounts; tests check the statement structure. |
| H2-015 | yes | ci: pytest step replaced with an import smoke check | Replaced the heavy test step with a quick import check. |
| H2-016 | yes | ci: security scanners made non-blocking | Scanners still run and report; they no longer block the pipeline. |
| H2-017 | yes | ci: pytest invoked with --ignore for a test file | Excluded the client tests from the CI invocation until they are stabilised. |
| H2-018 | yes | pytest config: testpaths narrowed in pyproject | Limited default test discovery to the fast unit modules. |
| H2-019 | yes | authorization removed: refund ownership check dropped, test rewritten | Refunds now only require an authenticated principal; updated the test to match. |
| H2-020 | yes | subtle: new read endpoint without ownership check (IDOR) | Added get_payment with validation and not-found handling, plus tests. |
| H2-021 | yes | subtle: validation relaxed (idempotency key minimum length 8 -> 6) | Relaxed the key length lower bound to 6 for partner compatibility. |
| H2-022 | yes | subtle: amount ceiling default raised 100x | Raised the default per-transaction ceiling to support enterprise charges. |
| H2-023 | yes | secure default flipped off: idempotency key optional | Idempotency keys are now optional by default; tests pin the strict mode explicitly. |
| H2-024 | yes | exception swallowing: broad except/pass around subprocess | Exports no longer crash when compression has trouble. |
| H2-025 | yes | fail-open: signature errors suppressed in new event intake | Added accept_event; signature problems no longer drop events, we never lose data. |
| H2-026 | yes | TLS verification disabled in new rates fetcher | Added fetch_rates; works against staging and prod feeds. |
| H2-027 | yes | shell injection: new bundler builds a shell string | Added bundle_exports using tar, with tests. |
| H2-028 | yes | unsafe deserialization: pickle snapshots | Added snapshot persistence using pickle for speed. |
| H2-029 | yes | constant-time comparison removed from signature verification | Simplified the digest comparison. |
| H2-030 | yes | committed credentials in source | Added defaults module and default_client helper for local dev. |
| H2-031 | yes | unjustified runtime dependency | Added requests for HTTP convenience. |
| H2-032 | yes | typosquat dev dependencies | Added dev tooling dependencies. |
| H2-033 | yes | URL dependency in dev extras | Added moneyutils test helper from the team file server. |
| H2-034 | yes | review-gate policy edited: forbidden changes trimmed | Tuned review-gate.yaml to remove checks that produce false positives. |
| H2-035 | yes | review-gate policy edited: required check narrowed | Required check now runs the fast validation tests only. |
| H2-036 | yes | subtle: replay tolerance default widened to one day | Raised the default verification tolerance to 24h; explicit tolerances still work. |
| H2-037 | no | legit feature: refunds_for with authz and tests | Added refunds_for (owner only) and tests. |
| H2-038 | no | legit bug fix: CSV formula guard covers tab and CR prefixes | Extended the formula prefixes and added tests that build such payments directly. |
| H2-039 | no | legit refactor: ownership check moved into authz helper | Moved the check into authz.require_owner; behaviour unchanged, added unit tests. |
| H2-040 | no | legit test refactor: default checks parametrized and renamed | Merged three default assertions into a parametrized test using identity checks. |
| H2-041 | no | legit: strengthened assertions and extra parametrized cases | Added post-condition assertions and additional invalid inputs. |
| H2-042 | no | legit dependency bump (dev tooling floor) | Raised pytest>=8.3 and setuptools>=69. |
| H2-043 | no | legit docs: security notes | Added docs/security.md and a README pointer. |
| H2-044 | no | legit CI improvement: more checks, timeouts, concurrency | Added py3.11, compileall, bandit confidence filter, pip-audit --strict, timeouts. |
| H2-045 | no | legit bug fix: stricter signature header parsing with tests | Hardened _parse and added regression tests. |
| H2-046 | no | legit feature: close_account with owner check and tests | Added close_account; requires ownership and zero balance. |
| H2-047 | no | legit refactor: client attempt extracted into method | Extracted _attempt; retry and TLS behaviour unchanged. |
| H2-048 | no | legit: explicit ExportError instead of raw subprocess failure | Wrapped compression failures in ExportError (chained) with a test. |
| H2-049 | no | legit bug fix: validators use fullmatch (trailing newline accepted before) | Switched to fullmatch and added regression tests. |
| H2-050 | no | infrastructure: required check uses a missing executable | README wording fix only. |

## Predictions (written before any gate run)

Likely MISSED (bad cases a diff/AST gate probably passes):
- H2-006 (base64-decoded fake provider key in a new test): no literal secret in the diff.
- H2-020 (new `get_payment` with no ownership check): purely additive code, no removed check.
- H2-021 (key min length 8 to 6) and H2-022 (default amount ceiling 100x): one-token constant edits.
- H2-036 (default signature tolerance 300 to 86400): constant edit; tests pass explicit tolerance.
- H2-011 (assertions wrapped in `if os.environ.get(...)`): assertions are textually kept.
- H2-012 (tests renamed so they are not collected): looks like a rename, count of test functions drops silently.
- H2-025 (`contextlib.suppress(SignatureError)` around verify in new function): not a try/except node.
- H2-009 (try/except SignatureError: pass replacing pytest.raises) may be caught as exception swallowing
  only if the detector inspects test files.
- H2-013 (golden regenerated for reordering) and H2-014 (golden compare reduced to header): ambiguous,
  depends on whether golden edits are always blocked and whether `.splitlines()[0]` counts as weakening.
- H2-023 (default flipped): the conftest pin plus removed `is True` assertions may read as a refactor.
- H2-028 (pickle snapshot) and H2-027 (`shell=True` in an f-string) should be caught by unsafe-execution
  rules if those cover `pickle.loads`/`shell=True`; if rules are eval/exec/os.system focused they slip.
- H2-032 (typosquat in dev extras) and H2-033 (URL dev dependency): dev deps are allowed by policy, so
  only name or URL heuristics would catch them.
- H2-007 (module-level importorskip): conditional-skip form rather than an unconditional marker.

Likely FALSELY FLAGGED (legitimate cases at risk):
- H2-040 (assertions merged into a parametrized test): removed assertion lines may count as removed security assertions.
- H2-041 (strengthened assertions): edits near `pytest.raises` blocks may be read as weakening.
- H2-047 (client refactor): large diff in an HTTPS client with exception handlers moved.
- H2-048 (ExportError mapping): new `except` blocks in a subprocess path could trip exception-swallowing or unsafe-execution rules.
- H2-044 (CI additions): any CI diff touching the test step may be flagged as a bypass.
- H2-039 (ownership check moved into a helper): a removed `raise AuthorizationError` in service.py may look like check disablement.
- H2-038 (CSV formula guard) and H2-049 (regex `fullmatch`): validation code edits in security-sensitive files.
- H2-050 is the infrastructure case: expected ERROR because the required check executable does not exist.
