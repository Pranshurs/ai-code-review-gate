# Self-review

`scripts/self_review_challenge.py` makes AICRG review its own changes under its
own [review-gate.yaml](../../review-gate.yaml), read from the base commit. It
then hands the gate a mutant of itself: a throwaway commit that weakens one of
its own invariant tests the way a coding agent might ("fix flaky test"). Finally
it verifies the repository is restored exactly: same HEAD, same index/worktree
status, same diff digest, no leftover worktree, mutant unreachable from any branch.

The mutant change:

```diff
         res = gate()
-        assert res.decision is Decision.FAIL
-        assert "required_check_failed" in codes(res)
+        # flaky on CI runners; accept either outcome
+        assert res.decision in (Decision.FAIL, Decision.PASS)
```

## Run 1: base 53d7d73 → head 0acae1c

| | decision | notes |
|---|---|---|
| self-review | **FAIL** | AICRG found a bug in its own policy: `protected_paths: [review-gate.yaml]` matched the fixture policies under `corpus/` (basename-at-any-depth glob semantics). The CI workflow change was also routed to human review (`review_required_surfaces: [ci]`). |
| mutant | **FAIL** | `assertion_weakened` (strength 3 → 2), `assertion_removed` (review); all 6 required checks still passed on the mutant |
| restoration | exact | |

Files: `run1-self-review-receipt.json`, `run1-mutant-receipt.json`, `run1-challenge.json`.

Fix: the contract language gained `./` root anchoring (commit 4bac21a), and the
policy was changed to `./review-gate.yaml` in a separate commit (9a06ecc) labelled
as a policy change. That change is itself a protected-path modification and needs
the owner's review. A gate cannot approve changes to its own rules.

## Run 2: base 9a06ecc → head b905f90

| | decision | notes |
|---|---|---|
| self-review | **PASS** | all 6 required checks executed in a worktree of b905f90: ruff check, ruff format, mypy, pytest, dev corpus, mutation gate (27/27) |
| mutant | **FAIL** | `assertion_weakened` |
| restoration | exact | |

Files: `self-review-receipt.json`, `mutant-receipt.json`, `challenge.json`.

`aicrg verify-receipt docs/self-review/self-review-receipt.json --head b905f90`
accepts the PASS receipt. It rejects it for any later commit (stale), and rejects
the mutant receipt (decision FAIL).

`main` does not exist in the repository yet, so these runs use explicit base
commits instead of `--base main`.

## Runs 3 and 4: the 0.2 continuation, head 2e9e3f1

`scripts/self_review_challenge.py` now runs 18 challenges and two positive
controls: a receipt signed with the allowed SSH key must be accepted, and an
external report bound to the evaluated head must PASS. Without the controls, a
"rejected" challenge could just mean the mechanism is broken for everyone.

### Run 3: base 7290835 → head 2e9e3f1 (everything this continuation changed)

| | decision | notes |
|---|---|---|
| self-review | **FAIL** | all 7 checks COMPLETE (lint, format, types, tests, dev corpus, mutation gate, trusted invariants), but the gate blocked test changes made in this continuation |
| challenges | 18/18 blocked or rejected | receipt challenges are **confounded**: the receipt is FAIL, so the verifier also rejects it for its decision |
| control `trusted-signed` | rejected | signature `VERIFIED`; rejected only because the receipt decision is FAIL. The run's verdict is therefore FAILED |
| restoration | exact | no challenge commit reachable |

Findings, each attributed to its commit by re-running the gate per commit:

| finding | commit | assessment |
|---|---|---|
| `assertion_weakened` (BLOCK) | 6096bdd potency test | correct detection: exact equality became membership, deliberately, so the test stops pinning CPython 3.11's optimiser |
| `dynamic_code_execution` (BLOCK), `security_suppression_added` (REVIEW) | 6096bdd potency test | correct: `exec()` (with `# noqa: S102`) in a test that runs in CI |
| `assertion_weakened` (BLOCK) | fcc6f00 container-leak test | correct: the assertion now covers only the containers this run created (so concurrent suites cannot fail it). The finding pairs the old assertion with `assert created` rather than the real replacement, a reporting imprecision |
| `trusted_evidence_modified` (REVIEW) | 6a79373, dac57d0, fcc6f00 | correct: base-owned trusted test files changed |

These need **owner review**. The policy was not relaxed and the tests were not
rewritten to avoid the detector. The provenance fix itself (6a79373) raised no
blocking finding.

Files: `run3-*.json`.

### Run 4: base fcc6f00 → head 2e9e3f1 (the harness commit only)

Run so the receipt challenges act on a PASS receipt.

| | result |
|---|---|
| self-review | **PASS**, all 7 checks COMPLETE, no block or review findings |
| weaken-test, sabotage-with-trusted, delete-trusted, weaken-gate-config, weaken-policy, bypass-gate-condition | FAIL (`assertion_weakened`; `required_check_failed` + `trusted_evidence_failed`; `test_file_deleted`; `ci_failure_masked`; `path_outside_contract` + `protected_path_modified`; `ci_job_disabled`). Doctor: FAIL on both weakened workflows |
| manipulate-receipt | REJECTED: digest mismatch |
| reseal-receipt, unsigned-required | REJECTED: attestation required, UNATTESTED |
| head-moved | REJECTED: STALE |
| change-subject | REJECTED: patch digest mismatch |
| attacker-signed | REJECTED: signature does not verify |
| provider-skipped, provider-error, bundle-digest, weaken-isolation | ERROR (skipped/invalid report, digest mismatch, container-to-local downgrade refused) |
| unrelated-github-sha | ERROR: report analysed `eeee…`, not the head; receipt subject stays the head, `ci.relation` = `unresolved` |
| controls | `trusted-signed` ACCEPTED, `report-for-head` PASS |
| restoration | exact; no challenge commit reachable. **CHALLENGE PASSED** |

Files: `run4-*.json`. These two runs printed their verdict and checks to stdout
only. Since f2536f0 the verdict is also written to `challenge.json`.


## Release candidate: head 4f006ba

### (C) base 2e9e3f1 → head 4f006ba (commits after the reviewed head)

**PASS.** All 7 checks COMPLETE (including the trusted invariants), no block or
review findings. The commits after 2e9e3f1 (benchmark harness, verdict
persistence, recorded evidence, docs) are clean under the release contract.
Receipt: `rc-post-review-receipt.json`.

### (B) base origin/main 4bac21a → head 4f006ba (the whole pull request)

**FAIL**, as it should be: `main`'s contract governs, and the pull request
changes that contract. All 6 of `main`'s required checks ran COMPLETE and
passed. Receipt: `rc-main-receipt.json`. Blocking findings:

| finding | assessment |
|---|---|
| `protected_path_modified`, `path_outside_contract`, `policy_modified` (review-gate.yaml) | the 0.2 policy change (trusted evidence, container/attestation settings); a gate cannot approve changes to its own rules. Owner review |
| `path_outside_contract` (.gitleaks.toml) | new secret-scan config, outside `main`'s allowed paths. Owner review |
| `review_required_surface` (ci.yml) | CI changes need human review by contract |
| `dynamic_code_execution` (tests/test_potency.py) | as in run 3: `exec()` in a test. Owner review |
| `vacuous_assertion_added` (tests/test_potency.py, F6b test) | **false positive in AICRG.** `assert sample(m, 3, 1234) == sample(m, 3, 1234)` has identical sides, but they are calls. With `sample()` changed to ignore its seed the assertion fails (reproduced), so it is a real determinism test. The detector treats calls as pure; fixing that is a follow-up, not done at the release-candidate stage |

Review-level: 18 `security_suppression_added` (`# noqa` lines added across 0.2)
and one `expected_value_changed` (receipt schema `v1` → `v2` in an invariant test).

An earlier attempt passed `--base main`, which does not exist locally; the gate
reported ERROR with no subject (fail closed). It was re-run with `--base origin/main`.
