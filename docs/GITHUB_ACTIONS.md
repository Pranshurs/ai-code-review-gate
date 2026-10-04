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
```

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

## This repository's own CI

`.github/workflows/ci.yml` runs lint, types, tests (3.11 to 3.13), the dev corpus
(all expectations must hold), the held-out corpora as ratchets (v1: at most the 6 recorded post-hoc misses;
v2: at most the 10 recorded mismatches), the mutation gate, a wheel build with a clean-venv
install, Bandit and pip-audit, and on pull requests the gate itself
(`uses: ./`) against this repository's `review-gate.yaml`.
