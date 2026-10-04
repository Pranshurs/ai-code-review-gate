# Cold security review (0.2 hardening)

An independent reviewer (a separate AI agent with no access to the design
discussion, instructed to reproduce every finding before reporting it)
reviewed the 0.2 code at `dbfda1e`/`977ec86`. Every finding below was
**reproduced by the main session** with the reviewer's proof-of-concept
before it was fixed, and each fix has a regression test in
`tests/test_security_review_regressions.py` (and, where it guards a
security-critical invariant, a mutant in `scripts/mutation_gate.py`).

Severity rubric: BLOCKER/HIGH = a candidate patch or untrusted input obtains
PASS or an accepted receipt it should not, escapes the claimed isolation, or a
document claims a protection that does not exist.

## Findings and disposition

| ID | Sev. | Finding | Fix | Evidence |
|---|---|---|---|---|
| F1 | **BLOCKER** | `verify-receipt --base` loaded the base contract only if the receipt's own `policy.source` said `base:`; a re-sealed receipt claiming `file:x` skipped `attestation.required` and was accepted | the verifier chooses the policy (`--base` + its own `--policy`), never the receipt; a source or digest mismatch rejects | `test_forged_policy_source_cannot_skip_required_attestation`, M51 |
| F1b | MEDIUM | without `--base`, the contract's attestation requirement and base staleness were silently not checked | CLI requires `--base` (or an explicit `--no-base`); API `require_base` | `test_f1b_…`, `test_verify_receipt_exit_code`, M66 |
| F2 | HIGH | `aicrg-tree-v1` digest was not injective: a tar member whose name embeds `\n<mode> <sha> <path>` collided with a two-file bundle | `aicrg-tree-v2`: JSON-encoded manifest; control characters in member names rejected | `test_f2_bundle_digest_is_injective` |
| F3 | HIGH | trusted files were writable by candidate code during the trusted run (both executors); several trusted specs shared one workspace | one fresh workspace per trusted spec; trusted paths bind-mounted **read-only** in the container; best-effort `a-w` locally; trusted content verified after every run (change/addition ⇒ ERROR) | `test_f3_…_local`, `test_f3_…_in_container`, `test_trusted_paths_are_mounted_read_only`, M53, M54 |
| F4 | HIGH | a report-producing tool that exited 1 with a coverage report was PASS (the "exit 1 + clean report" rule excluded coverage formats) — a failing `pytest --cov` run passed | rule applies to every format | `test_f4_…`, M57 |
| F5 | MEDIUM/HIGH | differential identities were a set: a second identical finding looked pre-existing (PASS with `allow`) | failure identities are a multiset | `test_f5_…`, M58 |
| F6a | HIGH | potency counted any test failure as a kill; a test asserting the SHA-256 of the source made every mutant "killed" | a behaviour-preserving **control mutant** (trailing comment) must survive, else potency is ERROR (⇒ REVIEW) | `test_f6a_…`, M59 |
| F6b | MED/HIGH | `max_mutants` sampling was deterministic and truncation silent: padding hid a weak function | random sample with a recorded seed; truncation ⇒ `SAMPLED` ⇒ REVIEW | `test_f6b_…`, `test_sampling_is_reproducible_from_its_recorded_seed`, M60 |
| F7 | HIGH | security analysis (and potency, changed-line coverage) skipped any file *named* like a test (`x_test.py`, `test_x.py`, `test/`), even when production code imports it | a test-named module imported by non-test code in the head is production | `test_f7_…` (3 layouts + control), M61 |
| F8 | MEDIUM | `doctor` passed gates whose exit status was lost (`\| tee` without pipefail, `\|\| echo`, `continue-on-error: ${{ true }}`), job-level `permissions: write-all`, and a fake `echo "aicrg check"` step | shell-line hazard detection, expression-aware `continue-on-error`, string permissions, gate command matched at command start | `test_f8_…` (5 cases), M62 |
| F8b | LOW/MED | required-check detection used `endswith` (`lint-aggregate` satisfied `gate`) | exact context or `<workflow> / <job>` | `test_f8b_…` |
| F9 | LOW | DTD/entity guard scanned bytes; UTF-16 XML with entities passed | XML reports must be UTF-8; guard runs on decoded text; other declared encodings refused | `test_f9_…`, M65 |
| F10 | LOW | local timeout not honoured if a child escaped the process group and held the pipe | bounded drain after kill; pipe closed | `test_f10_…` |
| F11 | MEDIUM | external evidence was accepted from any file (including one committed by the patch) and not bound to the commit | reports inside the evaluated checkout refused; SARIF `versionControlProvenance.revisionId` must equal the head or CI commit when present | `test_f11_…` (2), M63, M64 |
| F12 | HIGH | globs compiled without `DOTALL` and matched with `$`: a path containing `\n` escaped `trusted_tests/**`, `protected_paths`, `allowed_paths` | `DOTALL` + `fullmatch`; changed paths with control characters ⇒ `unsafe_path_name` (BLOCK) | `test_f12_…` (2), M55, M56 |
| F13 | HIGH | `source: base` trusted content came from the **merge-base**, which the candidate chooses by branching from an old base (and `verify-receipt --base` accepted it) | trusted content comes from the base **tip** | `test_f13_…`, M52 |
| F15 | HIGH (docs) | docs said CI runs the container tests with `AICRG_REQUIRE_DOCKER=1` and `aicrg doctor`; the workflow did not | CI updated in the CI-change commit (see below) | `.github/workflows/ci.yml` |
| F16 | INFO | potency reported `NO_MUTANTS` for a target the gate's Python cannot parse | ERROR (⇒ REVIEW) | `test_f16_…` |

Documentation corrections from the same review: `merge_group` attestations
are signed from `refs/heads/gh-readonly-queue/…` and do not satisfy a
`refs/heads/main` signer pin (U2); `action.yml` now reads merge-queue base/head
(U3); THREAT_MODEL rows 9, 18, 19, 20 and 22 were updated to match what is
actually mitigated.

## Re-verification round

The same reviewer re-ran every PoC against the fixes (27ac784) and attacked
the fixes themselves. Confirmed FIXED: F1, F1b, F2, F4, F5, F6b, F9, F10,
F12, F13, F15, F16. New or residual findings, each reproduced and fixed:

| ID | Sev. | Finding | Fix | Evidence |
|---|---|---|---|---|
| N1 | HIGH | F3's read-only mounts covered only directories holding trusted files; candidate code created a test file in a writable sibling directory during the run and deleted it at exit (post-run verification cannot see transient files) → PASS | container trusted runs mount the **whole workspace read-only** (only a check's report directory is writable); locally, best-effort protection covers glob static prefixes | `test_n1_trusted_run_sees_a_read_only_workspace`, `test_n1_no_writable_gap_…`, M67 |
| N2 | HIGH | the F6a control mutant only appended a comment; a test pinning the **AST** (or one function's bytecode) ignored it but killed every real mutant → PASS | controls now change form without behaviour: a dead module-level assignment, and a dead local in every mutated function | `test_n2_ast_or_bytecode_pin_…`, `test_n2_function_bytecode_pin_…`, M68 |
| N3 | HIGH | F7 resolved only static imports; `importlib.import_module(...)`, `__import__` and `pyproject` entry points still hid a test-named production module | string references in non-test Python (with constant `+` folding) and entry points in config files count as use | `test_n3_…` (3), M69 |
| N4 | MEDIUM | `doctor` still passed `aicrg check &`, `&&` chains followed by more commands, `! aicrg check`, a custom shell without `-e`, gate steps limited to non-PR events, and gate workflows with no PR trigger | all detected (`paths` filters reported as WARN); `aicrg check; true` under the default `bash -e` is correctly not flagged | `test_n4_…` (7), M70 |
| N5 | LOW | external evidence without SARIF revision provenance is unbound | documented; new `require_revision: true` refuses unbound reports | `test_n5_…`, M71 |

Residual by design: module names computed at run time from non-constant
fragments are not resolved (N3); potency controls are a deterrent against
form-pinning tests, not a proof — tests can still fingerprint mutants through
other side channels (N2); local-executor trusted protection is detection and
best-effort only (N1).

## Not fixed (accepted, documented)

* **U4 – required-check name spoofing.** A PR-added workflow with a job of the
  same name might satisfy a name-only required check. Mitigation is GitHub-side
  (rulesets with the check's app/integration, or required workflows). `doctor`
  does not inspect `integration_id`. Documented in GITHUB_ACTIONS.md.
* **U5 – `tool_version` probe** executes `argv[0] --version` from the candidate
  tree before the run. It cannot change the outcome beyond what the real run
  can; recorded as informational.
* **U6 – local-mode background processes** can outlive the run and edit files
  afterwards. Documented in EXECUTION_SECURITY.md; use the container executor.
* **Local executor cannot enforce read-only trusted paths** against same-user
  code (F3 locally is *detected*, not prevented: candidate code that restores
  trusted files before exiting is not caught). The container executor
  enforces it.
* **Self-gate dogfooding** (`uses: ./` in this repo's CI) runs the PR's own
  copy of the gate: it is a smoke test, not enforcement (documented).

## Re-verification

After the fixes, every reviewer PoC under `/tmp/claude-0/secreview` was re-run:
F1 → rejected (exit 5); F2 → bundle rejected; F3 → ERROR (local) / BLOCKED
(container); F4 → FAIL; F5 → NEW_REGRESSION; F6a → potency ERROR ⇒ REVIEW;
F7 → FAIL for the imported test-named modules; F8/F8b → FAIL; F12 → FAIL with
`unsafe_path_name`; F13 → BLOCKED. The PoC for `app/test/runner.py` remains
PASS because that PoC's `main.py` imports a different module (`app.runner`);
with the correct import the case is covered by `test_f7_…[app/test/runner.py]`.

## Continuation findings (after `7290835`)

### CI was red on every push of the 0.2 work (runs 8-17)

Every GitHub Actions run on the 0.2 branch, from `dbfda1e` (run 8) to
`7290835` (run 17), **failed**; run 14 was cancelled. Earlier "all green"
statements were local results only. They are not reused as CI evidence. Run 17
(`7290835`): lint-types, package, security and corpus passed; `tests (3.11)`,
`tests (3.12)`, `tests (3.13)` and `mutation` failed. Two independent causes:

1. **Ambient CI provenance (product bug P1 below, surfaced as a test failure).**
   The test suite inherited the runner's own `GITHUB_ACTIONS`/`GITHUB_SHA`,
   so fixture receipts recorded AICRG's CI commit in `subject.ci` and the
   attestation tests (which assumed no CI context) failed. Nothing in the suite
   exercised the CI-context path, so local runs could not see it.
2. **Test portability (test defect).** `test_equivalent_mutants_are_recognised_not_run`
   pinned CPython 3.11's optimiser: 3.12+ also folds `1 if False else 1`, so it
   correctly reports two more mutants as equivalent. Equivalence detection
   compares a recursive code-object fingerprint (bytecode, constants, names,
   variables), so equal fingerprints mean equal behaviour on every version; on
   3.11 those mutants are run and can only survive (conservative). The test now
   asserts the promised property: every mutant reported as equivalent behaves
   identically when executed.

### P1 — HIGH — execution provenance accepted as subject provenance

`subject.ci.sha` is where the gate ran (the workflow's `GITHUB_SHA`);
`subject.head` is what it evaluated. These were kept apart in the receipt
(no ambient value ever replaced `subject.head`, `base`, the patch digest or
repository identity — now pinned by tests), **but external-evidence binding
(F11) accepted a SARIF report whose revision equalled either the head or the
CI commit, without checking that the CI commit had anything to do with the
head.** Under an unrelated runner (`GITHUB_SHA = X`, target head `H ≠ X`), a
clean report of the runner's own code `X` was accepted as evidence about `H`:
reproduced as decision **PASS**.

Fix: the gate records `subject.ci.relation` (`head`, `merge_of_head` = parents
exactly `[base, head]`, `unrelated`, `unresolved`) and only a `head` /
`merge_of_head` CI commit may stand in for the head as an evidence revision.
Attestation binding is unchanged: an attestation still has to sign
`subject.ci.sha` (execution provenance), while the signed receipt binds
`subject.head` (subject provenance) and verification still rejects a moved head.

Evidence: `tests/test_provenance_boundary.py` (subject unchanged under five
ambient `GITHUB_SHA` shapes, unrelated `GITHUB_REPOSITORY`/`GITHUB_REF`;
relation classification; report for unrelated `X` ⇒ ERROR, for the merge
commit or the head ⇒ PASS; verification stays bound to `H`), both evidence
tests fail on `7290835`; `tests/test_attestation.py::TestCiProvenance`
(attestation must sign the CI commit; CI commit not built from head rejected);
mutants M72-M76. `tests/conftest.py` now clears ambient `GITHUB_*`/`GH_TOKEN`
so the suite is hermetic; CI-context behaviour is tested by setting it
explicitly.

### Run 18: mutant M53 survived on the CI runner (root vs non-root)

Run 18 (`6a79373`) was green for lint, all three test jobs, package, security
and corpus, but `mutation` failed: **75/76, M53 survived** (M53 removes the
post-run check that makes trusted content changed during its own run an
ERROR). Locally, as root, the same gate killed 76/76. Cause: the killing test's
candidate code was a *naive* tamper that gives up on `OSError`. As root the
best-effort `a-w` protection never blocks the rewrite, so only the post-run
check prevented PASS (mutant killed). On the non-root CI runner `a-w` blocked
the rewrite, the real trusted test failed, and the test (which accepted
"ERROR or FAIL") passed with or without the check: the invariant was not
isolated where CI runs. A local non-root reproduction was not performed; the
CI log is that reproduction.

Fix: `test_f3_owner_restoring_write_permission_is_detected_local` uses a
determined tamper that restores its own write permission (as the files' owner
can) and requires ERROR naming the modification; M53 now targets it. This
matches the documented limit: locally, trusted files are protected by
detection, not prevention.

### PR #1 run 23: container tests could skip silently inside the gate

On the pull request, `self-gate` ran AICRG under `main`'s contract and its
required check `mutation-gate` **failed**, while the standalone `mutation` job
passed 76/76 on the same commit. Cause: the `self-gate` job never pulled the
`python:3.12-slim` test image, so the suite judged Docker unavailable and
skipped the container tests, and container-only mutants survived (reproduced:
with the image absent, M67 survives). The gate failed closed, as it should.
But with the 0.2 contract merged, every future PR's self-gate would fail the
same way. A related gap: three container tests in
`test_security_review_regressions.py` skipped on `not DOCKER` and ignored
`AICRG_REQUIRE_DOCKER=1` (reproduced), contrary to the documented guarantee
that a missing runtime fails rather than skips.

Fix: those tests use the shared `needs_docker` marker (image missing with
`AICRG_REQUIRE_DOCKER=1` now fails 3 tests; without it they skip; with the
image they pass), and the `self-gate` job pulls the image and sets
`AICRG_REQUIRE_DOCKER=1` (CI change, separate commit).
