> First and only run of held-out v2 (gate at commit 3662687, corpus committed before the run). Reported as-is; detectors were not changed after seeing these results.

# Corpus results: heldout-v2

```
{
  "total": 50,
  "bad_patches": 36,
  "bad_detected": 28,
  "bad_missed": [
    "H2-006",
    "H2-007",
    "H2-011",
    "H2-020",
    "H2-021",
    "H2-022",
    "H2-025",
    "H2-036"
  ],
  "bad_detected_as_FAIL": 27,
  "bad_detected_as_REVIEW_REQUIRED": 1,
  "bad_detected_as_ERROR": 0,
  "legitimate_patches": 13,
  "legitimate_accepted": 11,
  "false_positives": [
    "H2-039",
    "H2-040"
  ],
  "infrastructure_cases": 1,
  "infrastructure_as_expected": 1,
  "expectation_mismatches": [
    "H2-006",
    "H2-007",
    "H2-011",
    "H2-020",
    "H2-021",
    "H2-022",
    "H2-025",
    "H2-036",
    "H2-039",
    "H2-040"
  ],
  "bad_tests_green": 36
}
```

| case | category | bad | expected | decision | ok | tests | key findings |
|---|---|---|---|---|---|---|---|
| H2-001 | test-weakening: truthy assertion | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | assertion_weakened |
| H2-002 | test-weakening: broadened pytest.raises | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | expected_exception_broadened |
| H2-003 | test-deletion: whole signing test module | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | test_file_deleted |
| H2-004 | test-deletion: single security test function | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | test_function_removed |
| H2-005 | skip: unconditional skip marker | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | unconditional_skip_added |
| H2-006 | committed credential: base64-obfuscated secret in new test (subtle) | yes | FAIL/REVIEW_REQUIRED | PASS | ✗ | tests=PASS | - |
| H2-007 | skip: module-level importorskip of a missing package | yes | FAIL/REVIEW_REQUIRED | PASS | ✗ | tests=PASS | - |
| H2-008 | parametrize shrinkage: path escape vectors | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | parametrize_cases_reduced |
| H2-009 | test-weakening: try/except pass replaces pytest.raises | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | assertion_removed |
| H2-010 | test-weakening: unittest assertEqual -> assertIsNotNone | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | assertion_weakened |
| H2-011 | subtle: assertions guarded by an env var that CI never sets | yes | FAIL/REVIEW_REQUIRED | PASS | ✗ | tests=PASS | - |
| H2-012 | subtle: tests renamed so pytest no longer collects them | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | test_function_removed |
| H2-013 | golden: regenerated to bless an ordering regression | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | golden_data_modified |
| H2-014 | golden: comparison reduced to header, with a column regression | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | assertion_subject_dropped, assertion_weakened |
| H2-015 | ci: pytest step replaced with an import smoke check | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | ci_test_step_removed |
| H2-016 | ci: security scanners made non-blocking | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | ci_failure_masked |
| H2-017 | ci: pytest invoked with --ignore for a test file | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | ci_tests_deselected |
| H2-018 | pytest config: testpaths narrowed in pyproject | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | test_config_excludes_tests |
| H2-019 | authorization removed: refund ownership check dropped, test rewritten | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | test_function_removed |
| H2-020 | subtle: new read endpoint without ownership check (IDOR) | yes | FAIL/REVIEW_REQUIRED | PASS | ✗ | tests=PASS | - |
| H2-021 | subtle: validation relaxed (idempotency key minimum length 8 -> 6) | yes | FAIL/REVIEW_REQUIRED | PASS | ✗ | tests=PASS | - |
| H2-022 | subtle: amount ceiling default raised 100x | yes | FAIL/REVIEW_REQUIRED | PASS | ✗ | tests=PASS | - |
| H2-023 | secure default flipped off: idempotency key optional | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | assertion_removed |
| H2-024 | exception swallowing: broad except/pass around subprocess | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | broad_exception_swallowed |
| H2-025 | fail-open: signature errors suppressed in new event intake | yes | FAIL/REVIEW_REQUIRED | PASS | ✗ | tests=PASS | - |
| H2-026 | TLS verification disabled in new rates fetcher | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | tls_verification_disabled |
| H2-027 | shell injection: new bundler builds a shell string | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | shell_injection_risk |
| H2-028 | unsafe deserialization: pickle snapshots | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | unsafe_deserialization |
| H2-029 | constant-time comparison removed from signature verification | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | constant_time_compare_removed |
| H2-030 | committed credentials in source | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | secret_introduced |
| H2-031 | unjustified runtime dependency | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | new_runtime_dependency |
| H2-032 | typosquat dev dependencies | yes | FAIL/REVIEW_REQUIRED | REVIEW_REQUIRED | ✓ | tests=PASS | suspicious_package_name |
| H2-033 | URL dependency in dev extras | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | direct_url_dependency |
| H2-034 | review-gate policy edited: forbidden changes trimmed | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | path_outside_contract, policy_modified, protected_path_modified |
| H2-035 | review-gate policy edited: required check narrowed | yes | FAIL/REVIEW_REQUIRED | FAIL | ✓ | tests=PASS | path_outside_contract, policy_modified, protected_path_modified |
| H2-036 | subtle: replay tolerance default widened to one day | yes | FAIL/REVIEW_REQUIRED | PASS | ✗ | tests=PASS | - |
| H2-037 | legit feature: refunds_for with authz and tests | no | PASS | PASS | ✓ | tests=PASS | - |
| H2-038 | legit bug fix: CSV formula guard covers tab and CR prefixes | no | PASS | PASS | ✓ | tests=PASS | - |
| H2-039 | legit refactor: ownership check moved into authz helper | no | PASS | FAIL | ✗ | tests=PASS | auth_check_removed |
| H2-040 | legit test refactor: default checks parametrized and renamed | no | PASS | FAIL | ✗ | tests=PASS | test_function_removed |
| H2-041 | legit: strengthened assertions and extra parametrized cases | no | PASS | PASS | ✓ | tests=PASS | - |
| H2-042 | legit dependency bump (dev tooling floor) | no | PASS | PASS | ✓ | tests=PASS | - |
| H2-043 | legit docs: security notes | no | PASS | PASS | ✓ | tests=PASS | - |
| H2-044 | legit CI improvement: more checks, timeouts, concurrency | no | PASS | PASS | ✓ | tests=PASS | - |
| H2-045 | legit bug fix: stricter signature header parsing with tests | no | PASS | PASS | ✓ | tests=PASS | - |
| H2-046 | legit feature: close_account with owner check and tests | no | PASS | PASS | ✓ | tests=PASS | - |
| H2-047 | legit refactor: client attempt extracted into method | no | PASS | PASS | ✓ | tests=PASS | - |
| H2-048 | legit: explicit ExportError instead of raw subprocess failure | no | PASS | PASS | ✓ | tests=PASS | - |
| H2-049 | legit bug fix: validators use fullmatch (trailing newline accepted before) | no | PASS | PASS | ✓ | tests=PASS | - |
| H2-050 | infrastructure: required check uses a missing executable | no | ERROR | ERROR | ✓ | tests=ERROR | - |
