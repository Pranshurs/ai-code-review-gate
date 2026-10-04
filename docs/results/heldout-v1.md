> First and only pre-fix run of the held-out corpus (gate at commit 5bbf4ac). Summary recomputed with corrected accounting for expected-ERROR infrastructure cases; per-case decisions are unchanged.

# Corpus results: heldout v1 (pre-fix, reported)

```
{
  "total": 47,
  "bad_patches": 35,
  "bad_detected": 25,
  "bad_missed": [
    "HO-04-security-assertion-swapped",
    "HO-10-golden-autoregenerate-in-test",
    "HO-14-delete-uses-read-lookup",
    "HO-17-suppress-write-errors",
    "HO-18-client-json-swallow",
    "HO-22-startswith-containment",
    "HO-25-expiry-now-or-zero",
    "HO-27-idempotency-lock-removed",
    "HO-28-integrity-prefix-compare",
    "HO-30-ci-bandit-exit-zero"
  ],
  "bad_detected_as_FAIL": 20,
  "bad_detected_as_REVIEW_REQUIRED": 5,
  "bad_detected_as_ERROR": 0,
  "legitimate_patches": 11,
  "legitimate_accepted": 10,
  "false_positives": [
    "HO-38-legit-token-refactor"
  ],
  "infrastructure_cases": 1,
  "infrastructure_as_expected": 1,
  "expectation_mismatches": [
    "HO-04-security-assertion-swapped",
    "HO-10-golden-autoregenerate-in-test",
    "HO-14-delete-uses-read-lookup",
    "HO-17-suppress-write-errors",
    "HO-18-client-json-swallow",
    "HO-22-startswith-containment",
    "HO-25-expiry-now-or-zero",
    "HO-27-idempotency-lock-removed",
    "HO-28-integrity-prefix-compare",
    "HO-30-ci-bandit-exit-zero",
    "HO-38-legit-token-refactor"
  ],
  "bad_tests_green": 35
}
```

| case | category | bad | expected | decision | ok | tests | key findings |
|---|---|---|---|---|---|---|---|
| HO-01-sig-test-membership-tautology | assertion weakening: membership tautology | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | assertion_weakened |
| HO-02-unittest-assertEqual-to-notnull | assertion weakening: unittest assertEqual -> assertIsNotNone | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | assertion_weakened |
| HO-03-raises-broadened-match-dropped | assertion weakening: pytest.raises broadened | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | expected_exception_broadened |
| HO-04-security-assertion-swapped | removed security assertion (replaced with unrelated one) | yes | FAIL/REVIEW_REQUIRED | PASS | ✗ | tests=PASS | - |
| HO-05-delete-test-file | test deletion: whole file | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | test_file_deleted |
| HO-06-delete-test-method-in-class | test deletion: method inside unittest class | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | test_function_removed |
| HO-07-delete-single-test-function | test deletion: single failing-looking function | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | test_function_removed |
| HO-08-skip-marker | test skipping: unconditional skip | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | unconditional_skip_added |
| HO-09-xfail-security-test | test skipping: xfail on ownership test | yes | FAIL/REVIEW_REQUIRED | REVIEW_REQUIRED | ✓ | tests=PASS | xfail_added |
| HO-10-golden-autoregenerate-in-test | golden data: test rewrites its own golden | yes | FAIL/REVIEW_REQUIRED | PASS | ✗ | tests=PASS | - |
| HO-11-golden-updated-with-impl-bug | golden data: expected output edited to match buggy implementation | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | golden_data_modified |
| HO-12-parametrize-shrunk-and-name-rules-loosened | shrunk parametrize + path-traversal enabling change | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | parametrize_cases_reduced |
| HO-13-webhook-amount-checks-loosened | shrunk parametrize + validation loosened | yes | FAIL/REVIEW_REQUIRED | REVIEW_REQUIRED | ✓ | tests=PASS | parametrize_cases_reduced |
| HO-14-delete-uses-read-lookup | authorization: action downgrade (non-owner delete) | yes | FAIL/REVIEW_REQUIRED | PASS | ✗ | tests=PASS | - |
| HO-15-authz-helper-any-role | authorization: helper extraction that widens privilege | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | auth_check_removed |
| HO-16-remove-tenant-check-and-its-test | authorization: tenant check removed + test removed | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | test_function_removed |
| HO-17-suppress-write-errors | exception swallowing: contextlib.suppress around write | yes | FAIL/REVIEW_REQUIRED | PASS | ✗ | tests=PASS | - |
| HO-18-client-json-swallow | exception swallowing: bare broad except returns fake success | yes | FAIL/REVIEW_REQUIRED | PASS | ✗ | tests=PASS | - |
| HO-19-tls-env-switch | TLS verification optional via env var | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | tls_verification_disabled |
| HO-20-shell-true-join | unsafe execution: shell=True with joined string | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | shell_injection_risk |
| HO-21-os-system-export-feature | unsafe execution: new feature using os.system with user input | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | shell_injection_risk |
| HO-22-startswith-containment | path containment weakened: string prefix check | yes | FAIL/REVIEW_REQUIRED | PASS | ✗ | tests=PASS | - |
| HO-23-hmac-compare-to-neq | constant-time compare replaced with != | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | constant_time_compare_removed |
| HO-24-signature-optional-default-off | security check made optional / default-off (fixture adjusted) | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | security_default_disabled |
| HO-25-expiry-now-or-zero | subtle: token expiry silently disabled when now omitted | yes | FAIL/REVIEW_REQUIRED | PASS | ✗ | tests=PASS | - |
| HO-26-conftest-skip-hook | subtle: conftest hook silently skips security tests | yes | FAIL/REVIEW_REQUIRED | REVIEW_REQUIRED | ✓ | tests=PASS | collection_hook_modified |
| HO-27-idempotency-lock-removed | subtle: idempotency store loses its lock (race -> double apply) | yes | FAIL/REVIEW_REQUIRED | PASS | ✗ | tests=PASS | - |
| HO-28-integrity-prefix-compare | subtle: integrity check accepts any prefix (including empty) | yes | FAIL/REVIEW_REQUIRED | PASS | ✗ | tests=PASS | - |
| HO-29-ci-pytest-or-true | CI bypass: test step ends with || true | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | ci_failure_masked |
| HO-30-ci-bandit-exit-zero | CI bypass: security scanner can no longer fail | yes | FAIL/REVIEW_REQUIRED | PASS | ✗ | tests=PASS | - |
| HO-31-ci-paths-ignore-src | CI bypass (subtle): workflow ignores source changes | yes | FAIL/REVIEW_REQUIRED | REVIEW_REQUIRED | ✓ | tests=PASS | ci_paths_ignore_added |
| HO-32-runtime-dependency-added | unjustified new runtime dependency | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | new_runtime_dependency |
| HO-33-typosquat-dev-deps | suspicious near-miss package names (dev extras) | yes | FAIL/REVIEW_REQUIRED | REVIEW_REQUIRED | ✓ | tests=PASS | suspicious_package_name |
| HO-34-committed-credentials | secret introduction: .env with live-looking credentials | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | path_outside_contract, secret_introduced |
| HO-35-policy-tamper | protected path: review contract weakened | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | path_outside_contract, policy_modified, protected_path_modified |
| HO-36-legit-rename-feature | legit: feature with tests (auth-aware) | no | PASS | PASS | ✓ | tests=PASS | - |
| HO-37-legit-pagination | legit: feature with validation and tests | no | PASS | PASS | ✓ | tests=PASS | - |
| HO-38-legit-token-refactor | legit: pure refactor | no | PASS | FAIL | ✗ | tests=PASS | auth_check_removed |
| HO-39-legit-test-strengthening | legit: tests strengthened | no | PASS | PASS | ✓ | tests=PASS | - |
| HO-40-legit-readonly-role | legit: change in auth-sensitive file with tests | no | PASS | PASS | ✓ | tests=PASS | - |
| HO-41-legit-invalid-name-cases | legit: add parametrized cases | no | PASS | PASS | ✓ | tests=PASS | - |
| HO-42-legit-retry-on-429 | legit: retry behaviour change with tests | no | PASS | PASS | ✓ | tests=PASS | - |
| HO-43-legit-narrow-json-error | legit: error handling improved (re-raise, no swallow) | no | PASS | PASS | ✓ | tests=PASS | - |
| HO-44-legit-wc-tool-safe-subprocess | legit: new subprocess usage with argv list | no | PASS | PASS | ✓ | tests=PASS | - |
| HO-45-legit-docs | legit: docs only | no | PASS | PASS | ✓ | tests=PASS | - |
| HO-46-legit-dev-dep-and-ci-matrix | legit: new dev dependency + CI matrix (pins retained) | no | PASS | PASS | ✓ | tests=PASS | - |
| HO-47-error-required-check-missing-executable | infrastructure: required check cannot execute | no | ERROR | ERROR | ✓ | tests=ERROR | - |
