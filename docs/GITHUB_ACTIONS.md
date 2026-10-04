# GitHub Actions

## Minimal workflow

```yaml
name: review-gate
on:
  pull_request:            # NOT pull_request_target (see "Threat boundary")

permissions:
  contents: read           # the gate needs nothing else

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0              # base and head must both be present
          persist-credentials: false
      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: "3.12"
      - run: pip install -e '.[dev]'   # whatever your required_checks need
      - uses: Pranshurs/ai-code-review-gate@<commit-sha>
        with:
          policy: review-gate.yaml     # read from the PR's BASE commit
          executor: container          # optional; may only make the contract stricter
          container-image: python:3.12-slim@sha256:<digest>
```

For trusted evidence bundles or external reports, call the CLI directly
(`aicrg check ... --bundle NAME=PATH --evidence NAME=PATH`) after an earlier
step has fetched them; the digest pinned in the base contract is what makes a
bundle trusted, not where it was downloaded from.

The Action:

1. installs AICRG from its own checkout (pin the Action by commit SHA);
2. runs `aicrg check --base <PR base SHA> --head <PR head SHA>`;
3. writes a Markdown summary to the job summary page;
4. uploads `review-receipt.json` as an artifact, even on failure;
5. exits 0 only on PASS (1 FAIL, 3 REVIEW_REQUIRED, 4 ERROR), so the job can be
   a required status check. It also sets output `decision`.

Example job summary for a blocked patch:

```
AI Code Review Gate
❌ Merge blocked
| Test integrity | FAIL |
- BLOCK assertion_weakened tests/test_auth.py:13: assertion on 'response.status' weakened (strength 3 -> 1)
  - before: assert response.status == 401
  - after:  assert response.status != 500
✓ tests (PASS)
```

Posting PR comments or check annotations is not implemented. It would need
`pull-requests: write` or `checks: write`, which v1 deliberately does not request.

## Threat boundary

* **Fork PRs run untrusted code.** `required_checks` executes the PR's code.
  Under `pull_request`, GitHub gives fork PRs a read-only token and no secrets,
  so that is acceptable. **Never** run this gate under `pull_request_target` or
  `workflow_run` with a checkout of the PR head: that executes attacker code with
  write tokens and secrets (the "pwn request" pattern). AICRG reports patches
  that *add* those triggers (`dangerous_trigger_added`), but it cannot protect a
  workflow you configured that way yourself.
* **Do not give the gate job secrets.** AICRG withholds credential-looking
  environment variables from checks, but a secret in the job environment is
  still reachable by malicious test code through other means (files, process
  inspection). The only real control is not providing it.
* **The patch can edit the workflow that runs the gate.** If AICRG runs from
  `.github/workflows/*.yml` in the PR, the PR can delete or neuter that step.
  AICRG reports it (`ci_test_step_removed`, `security_scanner_removed` for
  `aicrg`), but that report only matters if the gate itself still runs.
  To enforce:
  1. make the gate job a **required status check** in branch protection or a
     ruleset, so a PR that removes it cannot merge (the check never reports);
  2. ideally run it as an organisation **required workflow** (rulesets), which
     the PR cannot modify;
  3. put `review-gate.yaml` and `.github/` under CODEOWNERS review.
* **Pin everything.** Actions by commit SHA; the AICRG version by commit SHA or
  exact package version.
* **Stale results.** Enable "require branches to be up to date before merging",
  or run `aicrg verify-receipt --base origin/main` in the merge pipeline.

## Signing receipts

Attest the receipt in a **separate job that never checks out or executes
candidate code**. An `id-token: write` permission in the job that runs the
gate would let candidate code mint an OIDC token and sign anything as your
workflow. See [examples/aicrg-gate-attested.yml](examples/aicrg-gate-attested.yml)
and [RECEIPTS.md](RECEIPTS.md#github-artifact-attestations-sigstore).

An attestation made by a `pull_request` run is signed by
`<workflow>@refs/pull/N/merge` — a workflow file the PR itself can edit. It
proves which run produced the receipt, not that the run was honest. Verify
with a pinned `--signer-ref` (default `refs/heads/main`) so only runs of the
workflow from a protected ref count: a ruleset-required workflow, or a
`push` / `merge_group` run on the protected branch. Artifact attestations need
a public repository or GitHub Enterprise Cloud.

## `aicrg doctor`

```
aicrg doctor                 # static: workflows + review contract in this checkout
aicrg doctor --github --branch main [--check-name gate]   # + branch rules via the API
```

| check | FAIL when | WARN when |
|---|---|---|
| `gate-present` | no workflow runs `aicrg check` / the AICRG action | |
| `gate-not-masked` | `continue-on-error`, `\|\| true`, `set +e`, `if: false`, `--policy-from file` on the gate | |
| `gate-trigger` | gate runs under `pull_request_target` | |
| `gate-secrets` | the gate job references `secrets.*` (other than `GITHUB_TOKEN`) | |
| `gate-permissions` | the gate job has write permissions | |
| `dangerous-trigger` | `pull_request_target`/`workflow_run` that checks out PR code | such a trigger exists at all |
| `token-permissions` | workflow-wide write on PR-triggered workflows | no top-level `permissions:` |
| `action-pinning` | | actions not pinned to a commit SHA |
| `checkout-credentials` | | gate checkout persists the token |
| `policy` / `policy-protected` / `acceptance-config` | invalid contract | policy not protected; workflow changes neither protected nor routed to review |
| `executor` / `attestation` | | local executor; receipts not required to be attested |
| `github-required-check` | the gate is not a required status check on the branch | |
| `github-up-to-date` | | branches need not be up to date |
| `github-required-workflow` | | the gate runs from a PR-editable workflow (no ruleset-required workflow) |
| `github-rules` / `github-protection` | | — reported **UNKNOWN** when the token cannot read them |

UNKNOWN is never PASS: exit 4 if anything is UNKNOWN and nothing FAILs, 1 on
FAIL, 0 otherwise (`--strict` also fails on WARN). The static mode needs no
GitHub access; `--github` uses `GH_TOKEN`/`GITHUB_TOKEN` or the `gh` CLI.
Reading branch protection needs admin rights; reading effective branch rules
does not, but private repositories still need an authorised token.

## This repository's own CI

`.github/workflows/ci.yml` runs lint, types, tests (3.11 to 3.13), the dev corpus
(all expectations must hold), the held-out corpora as ratchets (v1: at most the 6 recorded post-hoc misses;
v2: at most the 10 recorded mismatches), the mutation gate, a wheel build with a clean-venv
install, Bandit and pip-audit, the container-isolation tests against a real
Docker daemon (`AICRG_REQUIRE_DOCKER=1`, so a missing runtime fails rather than
skips), `aicrg doctor` on itself, and on pull requests the gate itself
(`uses: ./`) against this repository's `review-gate.yaml`.
