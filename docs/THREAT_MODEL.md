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
| 1 | **Malicious patch author** weakens tests so a broken change passes | Diff-aware AST test-integrity analysis: removed/weakened assertions, broadened `pytest.raises`, vacuous asserts, early `return`, swallowed `AssertionError`, new skips/xfail, shrunk `parametrize`, deleted tests/files, golden-file edits, pytest/coverage/mypy/ruff config loosening, file-wide suppressions. Uncertain cases → REVIEW_REQUIRED. | **PARTIAL**: structural, not semantic. Weakening through helpers, fixtures, conftest behaviour, mocks, or same-shape logic changes is not detected. See docs/TEST_INTEGRITY.md and the held-out misses. |
| 2 | **Compromised / reward-hacking coding agent** produces a green but wrong patch and claims success | The agent's claims are not inputs. Evidence is re-executed from the exact head commit in a fresh worktree; untracked or uncommitted files are not used. | **MITIGATED** for "claimed tests pass": the gate runs them. **PARTIAL** for correctness: only as strong as the tests plus AICRG's structural checks. |
| 3 | **Prompt injection in source/comments** targets the optional reviewer model | Reviewer output is parsed as data. It can only add HYPOTHESIS findings (max REVIEW_REQUIRED), each citing an added line. It cannot remove findings, lower severity, or alter the contract. Instructions in patch text have no channel to the deterministic stages. | **MITIGATED** for decision integrity (tested: `test_prompt_injection_in_patch_is_inert`). Injection can still make the reviewer *miss* things or *add* noise (availability, not integrity). |
| 4 | **Test manipulation** via deleting or skipping the failing test | `test_file_deleted`, `test_function_removed`, `unconditional_skip_added` BLOCK under the default contract; moved/renamed tests with identical assertions are recognised and not blocked. | **MITIGATED** for direct forms; **PARTIAL** for indirect (e.g. `collect_ignore` changes are REVIEW, dynamic `pytest.skip` behind helper functions is missed). |
| 5 | **CI manipulation**: the patch edits workflows so tests stop running or stop failing | Workflow diff analysis: removed test commands, `\|\| true` / `continue-on-error` / `set +e`, constant-false `if`, deselect flags, removed triggers, removed scanners, `pull_request_target` added, widened permissions. | **PARTIAL**: AICRG reports what the patch changed, but if AICRG itself runs *from the patch's workflow file*, the patch can delete the AICRG step. Real enforcement needs the gate to run from a workflow the patch cannot change (required workflow / ruleset) and to be a required status check. See docs/GITHUB_ACTIONS.md. |
| 6 | **Policy manipulation**: the patch relaxes `review-gate.yaml` | Contract is read from the **base** commit by default. Editing it in the patch is reported (`policy_modified`, REVIEW_REQUIRED at minimum; FAIL if protected). Malformed or unknown policy keys → ERROR (fail closed). Duplicate YAML keys rejected. | **MITIGATED** (tested: `test_patch_cannot_relax_its_own_policy`, malformed-policy corpus/unit tests, mutation gate). Residual: `--policy-from file` trusts the operator's file. |
| 7 | **Dependency substitution / supply chain**: new runtime deps, typosquats, VCS/URL deps, extra index URLs, lockfile drift | Manifest delta (pyproject, requirements, setup.cfg, Pipfile, package.json) evaluated against `dependency_policy`; near-miss names vs a static popular list → REVIEW; index/source changes → REVIEW; manifest changed without lockfile → REVIEW. | **PARTIAL**: no vulnerability or malware database (run `pip-audit`/`osv-scanner`/dependency-review as required checks); transitive changes inside lockfiles are not analysed; the popular-name list is small and static. |
| 8 | **Stale evidence**: a PASS for commit A is used to merge commit B | Receipt binds base SHA, merge-base, head SHA, head tree, patch digest, contract digest, gate version. `aicrg verify-receipt` rejects a changed head, a different repository, a changed patch digest, a non-PASS decision, a different gate version, and with `--base` a moved target branch or changed base policy. | **MITIGATED** (tested + mutation gate). Requires the merge process to *call* verify-receipt; otherwise use "require branches to be up to date" + required status check. |
| 9 | **Forged or edited receipt** | `receipt_digest` detects naive edits. | **PARTIAL**: the digest is not a signature; anyone who can write the file can recompute it. Authenticity requires attesting the receipt (GitHub artifact attestations / Sigstore), which is not yet implemented. |
| 10 | **Runner compromise** (malicious code in the patch's tests attacks the machine running the gate) | Required checks run in a throwaway `git worktree` of the head SHA, with credential-looking environment variables removed (`TOKEN`, `SECRET`, `KEY`, `AWS_*`, ...), stdin closed, a timeout, and process-group kill. | **PARTIAL / documented assumption**: this is **not a sandbox**. Patch code runs with the invoking user's privileges and network access. Run AICRG on an ephemeral, unprivileged runner with no secrets (GitHub `pull_request` from forks satisfies this), or wrap `required_checks` in a container (`docker run --network none ...`). |
| 11 | **Repository-admin compromise**: an admin disables branch protection, edits the base policy, or bypasses the check | None; an admin defines the rules. | **OUT OF SCOPE**. Use org-level rulesets, audit logs, and two-person review of policy changes (CODEOWNERS on `review-gate.yaml`). |
| 12 | **Untrusted fork execution**: fork PR code runs with repository secrets | Documented workflow uses `pull_request` (not `pull_request_target`), `permissions: contents: read`, no secrets, SHA-pinned actions; the gate flags patches that *add* `pull_request_target`/`workflow_run` triggers or widen permissions. | **MITIGATED** for the shipped workflow. A user who adds `pull_request_target` and checks out PR code re-creates the classic "pwn request" hole; AICRG flags it but cannot stop it in someone else's workflow. |
| 13 | **Gate denial of service / infrastructure failure** (tool missing, timeout, git error, analyser crash) | Every stage is wrapped; any exception or uncompleted check becomes ERROR. ERROR is never PASS (decision matrix tested; CLI crash → exit 4). | **MITIGATED** (tested + mutation gate). Availability itself is not guaranteed. |
| 14 | **Terminal / log injection** through file names, test output or reviewer text | Control characters and ANSI/OSC escape sequences stripped from all rendered text; Markdown summary escapes table/inline syntax. | **MITIGATED** for rendering. Receipt JSON preserves raw strings by design (JSON-escaped). |
| 15 | **Secret leakage through the gate** (receipt, logs, reviewer request) | Secret matches are redacted in findings; check output tails are scrubbed for common token formats; reviewer requests are redacted and only include changed lines. | **PARTIAL**: pattern-based; a secret in an unknown format printed by a test will appear in the bounded output tail. |
| 16 | **Evasion by obfuscation** (e.g. `getattr(subprocess, "r"+"un")(cmd, shell=1)`, base64-decoded code) | Constant-folded variants are not modelled. | **OUT OF SCOPE** for V1 regression rules; run Semgrep/CodeQL/Bandit as required checks for deeper analysis. |
| 17 | **Semantic regressions with no syntactic signal** (retry loop now double-charges, wrong rounding) | Required tests + optional reviewer-model hypotheses. | **OUT OF SCOPE** for deterministic analysis. A hypothesis is never proof (`HYPOTHESIS` kind). |

## What a PASS means

A PASS means: for the recorded base/head/patch/policy, (a) every required check
was executed from the head commit and exited 0, (b) no deterministic or
heuristic rule in this gate version fired at BLOCK or REVIEW, and (c) nothing
in the gate failed to complete. It does **not** mean the patch is correct or
secure. It means the evidence the contract asks for exists and is intact as far
as AICRG can tell.

## Assumptions an operator must make true

1. The gate runs from a workflow or machine the patch cannot modify (required workflow, ruleset, or external runner), and is a **required status check**.
2. The policy file is on the protected base branch and changes to it need review (CODEOWNERS).
3. The runner executing `required_checks` holds no secrets and is ephemeral.
4. The AICRG version is pinned.
5. Merges require the branch to be up to date with the base, or the merge process runs `aicrg verify-receipt --base <target>`.
