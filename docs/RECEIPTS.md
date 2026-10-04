# Gate receipts

Every `aicrg check` writes a receipt: `.aicrg/receipts/<head-sha>.json` by default,
or `--receipt PATH`. It records exactly what was evaluated, under which rules,
with what evidence, and what was decided.

## Schema `aicrg.receipt/v2`

| field | content |
|---|---|
| `schema` | `"aicrg.receipt/v2"` (v1 receipts are from gate 0.1.x and are rejected by a 0.2 verifier) |
| `gate` | `{name, version}` |
| `decision` | `PASS` \| `FAIL` \| `REVIEW_REQUIRED` \| `ERROR` |
| `reasons` | ordered human-readable reasons (blocking, then errors, then review) |
| `subject.repository` | `{remote (credentials stripped), root_commits}` |
| `subject.base_ref` / `head_ref` | what the user typed |
| `subject.base` / `merge_base` / `head` / `head_tree` | full SHAs |
| `subject.patch_digest` | `sha256:` of the canonical `git diff --binary --full-index` merge_base..head |
| `subject.files` | per file: status, old/new path, added/removed line counts, binary |
| `subject.working_tree_dirty` | uncommitted changes existed and were **not** evaluated |
| `subject.ci` | **execution** provenance, on GitHub Actions: `{provider, repository, sha, ref, event, workflow_ref, run_id, run_attempt, relation}`; `sha` is the commit an attestation signs. It never replaces `base`/`head` (**subject** provenance): the runner may belong to another repository. `relation` says how `sha` relates to the subject: `head`, `merge_of_head` (parents exactly `[base, head]`, GitHub's pull_request merge), `unrelated` (a commit of this repository that is neither) or `unresolved` (not in this repository) |
| `subject.files_excluded_from_analysis` | count, if `exclude_from_analysis` matched |
| `policy` | `{source, repo_path, raw_digest, contract_digest, contract}` |
| `risk` | `{level, surfaces, evidence[{surface, file, reason}]}` |
| `sections` | per area: PASS / FAIL / REVIEW / ERROR / NONE / OFF |
| `checks[]` | `{name, argv, status, exit_code, started_at, finished_at, duration_ms, output_sha256, output_tail, reason, tool_version, source, revision, provider_status, report?, report_digest?}`; `source` = head / base / bundle / external, `revision` = head / base (differential), `provider_status` = COMPLETE / FINDINGS / SKIPPED / ERROR / TIMEOUT (`status` is derived from it) |
| `execution` | executor description: `local` (isolation `none`) or `container` (runtime, image, resolved image ID, network, user, limits) |
| `evidence[]` | per evidence item: `{name, source, required, head_status, base_status?, classification?}` (differential classes: see docs/EVIDENCE.md) |
| `trusted_evidence[]` | per overlay: `{name, source, digest, files, candidate_files_replaced, candidate_files_removed}` |
| `test_potency` | `{engine, status, changed_production_lines, relevant_mutants, killed, killed_by_timeout, survived, equivalent, not_run, suppressed_lines, mutants[]}` or `{status: not_run}` |
| `findings[]` | `{code, category, severity, kind, message, file, line, before, after, provider}` |
| `summary` | counts; `deterministic_failures`, `heuristic_failures` (codes) |
| `test_integrity` | result + test/assertion counts before and after |
| `dependencies[]` | `{change, ecosystem, name, kind, before, after, source}` |
| `llm_review` | `{status, provider, model, model_version, request_sha256, hypotheses, discarded_uncited, error}` |
| `errors[]` | `{stage, message}`; any entry without a blocking finding makes the decision ERROR |
| `environment` | python, platform, machine, git, aicrg, `env_vars_withheld_from_checks` |
| `timestamps`, `timings_ms` | wall-clock data (not deterministic) |
| `receipt_digest` | `sha256:` over the canonical JSON of everything else |

Canonical JSON: UTF-8, sorted keys, `(",", ":")` separators, no NaN.

Secrets matched by the secret detector are redacted (`AKIA…[20 chars redacted]`)
and check output tails are scrubbed for common token formats before they are
written. The full output is represented only by `output_sha256`.

## Verifying a receipt

```
aicrg verify-receipt RECEIPT [--head HEAD] [--base origin/main]
    [--require-attestation] [--attestation github|ssh] ...
```

Output always states integrity and authenticity separately:

```
INTEGRITY: VERIFIED
AUTHENTICITY: UNATTESTED
```

It is rejected (exit 5) when any of these hold:

| check | catches |
|---|---|
| schema unsupported | unknown format |
| `receipt_digest` mismatch | naive edits to any field (INTEGRITY: FAILED) |
| decision ≠ PASS (unless `--allow-non-pass`) | using a FAIL/REVIEW receipt as approval |
| gate version ≠ verifier version | rules changed between evaluation and merge |
| `head` ≠ current `--head` | **stale receipt: new commits after evaluation** |
| root commits differ | receipt from another repository |
| recomputed patch digest ≠ recorded | forged subject with a recomputed digest |
| `subject.ci.sha` is a local commit that is not a merge built from `head` | receipt claims a CI commit unrelated to the head |
| with `--base`: base tip moved | merge result was never evaluated |
| with `--base`: base contract digest changed | policy changed since evaluation |
| attestation required (base contract `attestation.required`, or `--require-attestation`) and AUTHENTICITY ≠ VERIFIED | unsigned, forged or wrongly signed receipt |
| an attestation is present but invalid | wrong signer, wrong commit, tampered content |

## Integrity is not authenticity

`receipt_digest` is **not a signature**. Anyone who can write the file can
recompute it; it detects accidents and naive tampering only
(`test_edited_and_resealed_receipt_fails_authenticity` shows a re-sealed
receipt passing integrity and failing authenticity). AICRG does no
cryptography of its own; it verifies attestations made by standard tools.

### GitHub artifact attestations (Sigstore)

Produce in CI, in a job that does **not** execute candidate code (see
[examples/aicrg-gate-attested.yml](examples/aicrg-gate-attested.yml)):

```yaml
- uses: actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8 # v4.2.2
  with:
    subject-path: review-receipt.json
```

Verify:

```
aicrg verify-receipt review-receipt.json --base origin/main --require-attestation \
  --attestation github --repo OWNER/REPO \
  --signer-workflow OWNER/REPO/.github/workflows/aicrg-gate.yml --signer-ref refs/heads/main
```

AICRG runs `gh attestation verify` (signature, Rekor inclusion, subject digest
= SHA-256 of the receipt file) and then checks the certificate claims itself:

1. `sourceRepositoryURI` is the expected repository;
2. `buildSignerURI` equals `https://github.com/<signer_workflow>@<signer_ref>`
   exactly. A `pull_request` run is signed by `…@refs/pull/N/merge`, a workflow
   the PR can edit; it does not satisfy a pin on `refs/heads/main`. Pin the
   ref the enforcing workflow actually runs from (e.g. a ruleset-required
   workflow pinned to `refs/heads/main`). `merge_group` runs are signed from
   `refs/heads/gh-readonly-queue/…` and do not match a `refs/heads/main` pin;
3. `sourceRepositoryDigest` equals the commit the gate ran on
   (`subject.ci.sha`, else `subject.head`).

In a contract:

```yaml
attestation:
  required: true
  method: github
  repository: OWNER/REPO
  signer_workflow: OWNER/REPO/.github/workflows/aicrg-gate.yml
  signer_ref: refs/heads/main      # default
```

Artifact attestations are available for public repositories, and for private
repositories only on GitHub Enterprise Cloud. In this (private) repository the
GitHub path is therefore exercised with a stub `gh` in tests
(`tests/test_attestation.py::TestGithub`), not against Sigstore.

### SSH signatures (offline / self-hosted)

```
aicrg receipt sign review-receipt.json --key /secure/gate_key   # ssh-keygen -Y sign
aicrg verify-receipt review-receipt.json --base origin/main
```

with a contract such as:

```yaml
attestation:
  required: true
  method: ssh
  allowed_signers: .aicrg/allowed_signers   # read from the BASE commit
  identity: gate@example.org
```

The `allowed_signers` file is read from the base commit, so a patch that adds
its own key changes nothing (`test_base_contract_requires_attestation_and_pins_signers`).
The signing key must live where candidate code never runs.

### in-toto mapping

`aicrg receipt statement RECEIPT` prints an in-toto Statement v1 with the head
commit (`gitCommit`) and the receipt digest as subjects and the receipt as the
predicate (`predicateType: https://github.com/Pranshurs/ai-code-review-gate/receipt/v2`).
This is a mapping for future custom-predicate attestations. **AICRG does not
claim SLSA conformance.**
