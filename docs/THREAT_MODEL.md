# Threat model

AICRG answers one question: *is there enough independent, reproducible evidence
to accept this patch?* This document states who might try to make that answer
wrong, what AICRG does about it, and where it stops. Controls are classified:

* **MITIGATED**: a deterministic control exists, is tested (unit, corpus or mutation gate), and its residual risk is stated.
* **PARTIAL**: a control exists but is heuristic, bypassable by a determined adversary, or depends on deployment.
* **OUT OF SCOPE**: AICRG does not address it; a named external control should.

## Assets

1. The **merge decision** for a patch (PASS / FAIL / REVIEW_REQUIRED / ERROR).
2. The **review contract** (policy) that defines what evidence is required.
3. The **receipt** that records which exact inputs produced the decision.
4. **Secrets** available where the gate and the patch's checks run.

## Trust boundaries

```
 trusted (if deployment is right)             untrusted
 ─────────────────────────────────            ───────────────────────────────────────
 base branch content (incl. policy)           head commit: code, tests, CI files, configs,
 aicrg package version pinned by operator     dependency manifests, comments, docstrings
 runner OS / Python / git                     agent's explanation and claimed test results
 branch protection settings                   reviewer-model output
```

The patch's **code runs** during evidence collection (`required_checks`). That
is the dangerous step; see "Untrusted code execution".

## Adversaries and attacks

| # | Adversary / attack | Control in AICRG | Status |
|---|---|---|---|
| 1 | **Malicious patch author** weakens tests so a broken change passes (or names a production module like a test so analysers skip it — review F7, now analysed when production code imports it) | Diff-aware AST test-integrity analysis (removed/weakened assertions, broadened `pytest.raises`, vacuous asserts, early `return`, swallowed `AssertionError`, new skips/xfail, shrunk `parametrize`, deleted tests/files, golden edits, config loosening, suppressions). **Trusted evidence** (0.2): base-owned or digest-pinned tests run against the candidate code regardless of what the patch did to its own tests. **Test potency** (0.2): surviving mutants of changed code → REVIEW. | **MITIGATED** for assertions placed under trusted evidence (tested: `test_weakened_visible_test_is_green_but_trusted_test_blocks`, conftest/symlink/deletion variants, mutation gate M28-M31). **PARTIAL** otherwise: structural analysis is not semantic; candidate code can still detect it is under test. |
| 2 | **Compromised / reward-hacking coding agent** produces a green but wrong patch and claims success | The agent's claims are not inputs. Evidence is re-executed from the exact head commit in a fresh worktree; untracked or uncommitted files are not used. | **MITIGATED** for "claimed tests pass": the gate runs them. **PARTIAL** for correctness: only as strong as the tests plus AICRG's structural checks. |
| 3 | **Prompt injection in source/comments** targets the optional reviewer model | Reviewer output is parsed as data. It can only add HYPOTHESIS findings (max REVIEW_REQUIRED), each citing an added line. It cannot remove findings, lower severity, or alter the contract. Instructions in patch text have no channel to the deterministic stages. | **MITIGATED** for decision integrity (tested: `test_prompt_injection_in_patch_is_inert`). Injection can still make the reviewer *miss* things or *add* noise (availability, not integrity). |
| 4 | **Test manipulation** via deleting or skipping the failing test | `test_file_deleted`, `test_function_removed`, `unconditional_skip_added` BLOCK under the default contract; moved/renamed tests with identical assertions are recognised and not blocked. | **MITIGATED** for direct forms; **PARTIAL** for indirect (e.g. `collect_ignore` changes are REVIEW, dynamic `pytest.skip` behind helper functions is missed). |
| 5 | **CI manipulation**: the patch edits workflows so tests stop running or stop failing | Workflow diff analysis (removed test commands, `\|\| true`, `continue-on-error`, `set +e`, constant-false `if`, deselects, removed triggers/scanners, `pull_request_target` added, widened permissions). `aicrg doctor` (0.2) reports a missing/masked gate, self-policy, pwn-request patterns, broad tokens, unpinned actions, and with `--github` whether the gate is a required check from a ruleset-required workflow. | **PARTIAL**: if the gate runs from a PR-editable workflow, the PR can neuter it; enforcement needs a required status check from a workflow the PR cannot change (ruleset-required workflow or external runner). Real-world track: reverting `permissions:` blocks, SHA pins or `persist-credentials: false` is **not** detected by the patch analyser (RW17-RW20). |
| 6 | **Policy manipulation**: the patch relaxes `review-gate.yaml` | Contract is read from the **base** commit by default. Editing it in the patch is reported (`policy_modified`, REVIEW_REQUIRED at minimum; FAIL if protected). Malformed or unknown policy keys → ERROR (fail closed). Duplicate YAML keys rejected. | **MITIGATED** (tested: `test_patch_cannot_relax_its_own_policy`, malformed-policy corpus/unit tests, mutation gate). Residual: `--policy-from file` trusts the operator's file. |
| 7 | **Dependency substitution / supply chain**: new runtime deps, typosquats, VCS/URL deps, extra index URLs, lockfile drift | Manifest delta (pyproject, requirements, setup.cfg, Pipfile, package.json) evaluated against `dependency_policy`; near-miss names vs a static popular list → REVIEW; index/source changes → REVIEW; manifest changed without lockfile → REVIEW. | **PARTIAL**: no vulnerability or malware database (run `pip-audit`/`osv-scanner`/dependency-review as required checks); transitive changes inside lockfiles are not analysed; the popular-name list is small and static. |
| 8 | **Stale evidence**: a PASS for commit A is used to merge commit B | Receipt binds base SHA, merge-base, head SHA, head tree, patch digest, contract digest, gate version. `aicrg verify-receipt` rejects a changed head, a different repository, a changed patch digest, a non-PASS decision, a different gate version, and with `--base` a moved target branch or changed base policy. | **MITIGATED** (tested + mutation gate). Requires the merge process to *call* verify-receipt; otherwise use "require branches to be up to date" + required status check. |
| 9 | **Forged or edited receipt** | `receipt_digest` detects naive edits (integrity). **Attestation** (0.2): GitHub artifact attestations (Sigstore) verified with pinned repository, signer workflow **and ref**, and signed commit; or SSH signatures with `allowed_signers` read from the base. A contract can require authenticity. | **MITIGATED** where attestation is required, the verifier passes `--base` (the CLI requires it), and the signer runs from a protected ref in a job that executes no candidate code (tested: re-sealed receipt fails authenticity, attacker key, wrong commit, PR-ref signer, forged `policy.source` (review F1); M44-M47, M51, M66). **PARTIAL** without that: integrity only. GitHub attestations need a public repo or GHEC; not exercised against Sigstore in this private repo. |
| 10 | **Runner compromise** (malicious code in the patch's tests attacks the machine running the gate) | `ContainerExecutor` (0.2): unprivileged numeric user, caps dropped, no-new-privileges, read-only rootfs, network off, no host env, only a throwaway export mounted (no `.git` link), CPU/memory/PID/time limits; base contract's executor cannot be downgraded; missing runtime → ERROR. `LocalExecutor`: env filtering + timeouts only, documented as trusted-code mode. | **MITIGATED** to container-isolation strength with the container executor (real-Docker adversarial probe in `test_execution_boundary.py`; M41-M43). Not a guarantee against kernel/runtime escape. **PARTIAL / assumption** with the local executor: use only on ephemeral, secret-free runners. |
| 11 | **Repository-admin compromise**: an admin disables branch protection, edits the base policy, or bypasses the check | None; an admin defines the rules. | **OUT OF SCOPE**. Use org-level rulesets, audit logs, and two-person review of policy changes (CODEOWNERS on `review-gate.yaml`). |
| 12 | **Untrusted fork execution**: fork PR code runs with repository secrets | Documented workflow uses `pull_request` (not `pull_request_target`), `permissions: contents: read`, no secrets, SHA-pinned actions; the gate flags patches that *add* `pull_request_target`/`workflow_run` triggers or widen permissions. | **MITIGATED** for the shipped workflow. A user who adds `pull_request_target` and checks out PR code re-creates the classic "pwn request" hole; AICRG flags it but cannot stop it in someone else's workflow. |
| 13 | **Gate denial of service / infrastructure failure** (tool missing, timeout, git error, analyser crash) | Every stage is wrapped; any exception or uncompleted check becomes ERROR. ERROR is never PASS (decision matrix tested; CLI crash → exit 4). | **MITIGATED** (tested + mutation gate). Availability itself is not guaranteed. |
| 14 | **Terminal / log injection** through file names, test output or reviewer text | Control characters and ANSI/OSC escape sequences stripped from all rendered text; Markdown summary escapes table/inline syntax. | **MITIGATED** for rendering. Receipt JSON preserves raw strings by design (JSON-escaped). |
| 15 | **Secret leakage through the gate** (receipt, logs, reviewer request) | Secret matches are redacted in findings; check output tails are scrubbed for common token formats; reviewer requests are redacted and only include changed lines. | **PARTIAL**: pattern-based; a secret in an unknown format printed by a test will appear in the bounded output tail. |
| 16 | **Evasion by obfuscation** (e.g. `getattr(subprocess, "r"+"un")(cmd, shell=1)`, base64-decoded code or secrets) | Not modelled by AICRG's own rules. **Evidence providers** (0.2): Semgrep/CodeQL/Bandit/secret scanners ingested as SARIF; a required provider that is skipped/errors/times out makes the gate ERROR. | **OUT OF SCOPE** for AICRG rules; **delegated** to specialist scanners whose absence is now visible. |
| 17 | **Semantic regressions with no syntactic signal** (retry loop now double-charges, a tolerance constant ×288) | Trusted evidence encoding the property; test potency (surviving mutants → REVIEW; exploratory: 3 of 8 held-out v2 misses become REVIEW); differential runs; optional reviewer-model hypotheses (≤ REVIEW). | **PARTIAL**: no deterministic analysis proves semantics; AICRG makes weak evidence visible rather than claiming correctness. |

| 18 | **Evidence forgery inside the workspace**: the patch commits a clean report at the report path, symlinks it elsewhere, makes a tool exit 0 without writing, or plants an "external" report | Reports deleted before the run; after the run must be a regular, non-symlinked file inside the workspace; tool exit must be 0/1; exit 1 with a clean report (any format, including coverage) is FINDINGS; missing → ERROR. External reports inside the evaluated checkout are refused; a SARIF report naming another revision is refused. | **MITIGATED** (tests + M40, M57, M63, M64; review F4, F11). External reports without revision provenance are trusted to the operator. |
| 19 | **Trusted-evidence subversion**: edit/delete/add files under trusted paths (including names with newlines), replace the directory with a symlink, swap a bundle, branch from an old base, rewrite trusted files while they run | Overlay makes trusted paths identical to the **base tip** (additions removed, symlinks replaced, never followed); globs are newline-safe and control-character paths BLOCK; bundles verified by the injective `aicrg-tree-v2` digest pinned in the base contract, else ERROR; one workspace per trusted spec; trusted paths read-only in the container and verified after each run (change ⇒ ERROR); candidate touches reported (`trusted_evidence_modified`). | **MITIGATED** for content with the container executor (review F2, F3, F12, F13; M28-M31, M52-M56). Local executor: tampering is *detected*, not prevented (code that restores the files before exit is not caught). **PARTIAL** for execution: candidate code still runs and can hook the runner from outside trusted paths unless the trusted command pins config (`-c`, `--confcutdir`). |
| 20 | **Pre-existing failure laundering**: a new failure hidden among old ones, including a duplicate of an existing finding | Differential base/head runs compare failure-identity **multisets**; new identities or higher counts are NEW_REGRESSION; without structured identities both-failing is REVIEW, never "allowed". | **MITIGATED** for structured reports (M35-M37, M58; review F5). |
| 21 | **Attestation from a PR-controlled workflow**: a `pull_request` run signs a receipt from a workflow file the PR edited | Verification pins `buildSignerURI` to `<workflow>@<protected ref>`; PR refs do not match. Attesting is documented as a separate job without candidate code (an `id-token: write` gate job would let candidate code sign anything). | **MITIGATED** in verification (M46); deployment must follow the two-job pattern. |
| 22 | **Gaming test potency**: no-mutate pragmas, unmeasurable baselines, timeouts, tests that pin the source text (self-hash), padding so the weak spot falls outside the sample | Pragmas reported (REVIEW); baseline failure, tool error, budget exhaustion → REVIEW/ERROR; a behaviour-preserving control mutant must survive (else ERROR); random recorded-seed sampling and truncation ⇒ SAMPLED ⇒ REVIEW. | **PARTIAL**: the known gaming routes are closed (M32-M34, M59, M60; review F6a/F6b), but potency is a heuristic signal: tests can still distinguish mutants by side channels other than source text, and potency does not see test-only manipulation or missing checks in new code. |

## What a PASS means

A PASS means: for the recorded base/head/patch/policy, (a) every required check
was executed from the head commit and exited 0, (b) no deterministic or
heuristic rule in this gate version fired at BLOCK or REVIEW, and (c) nothing
in the gate failed to complete. It does **not** mean the patch is correct or
secure. It means the evidence the contract asks for exists and is intact as far
as AICRG can tell. Where the contract asks for trusted evidence, that evidence
came from the base or a pinned bundle, not from the patch.

## Assumptions an operator must make true

1. The gate runs from a workflow or machine the patch cannot modify (required workflow, ruleset, or external runner), and is a **required status check**.
2. The policy file is on the protected base branch and changes to it need review (CODEOWNERS).
3. The runner executing evidence holds no secrets and is ephemeral; or the
   contract requires the container executor.
6. Receipts that authorise merges are attested in a job that runs no candidate
   code, from a protected ref, and verified with a pinned signer workflow + ref.
4. The AICRG version is pinned.
5. Merges require the branch to be up to date with the base, or the merge process runs `aicrg verify-receipt --base <target>`.
