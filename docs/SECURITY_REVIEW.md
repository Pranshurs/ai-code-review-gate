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
