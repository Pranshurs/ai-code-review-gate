# Review contract

The contract (`review-gate.yaml`) says what evidence must exist before a patch
can be accepted. It is deliberately small.

## Where it is read from

| Mode | Source | When to use |
|---|---|---|
| default | `review-gate.yaml`, `review-gate.yml`, `.aicrg.yaml` or `.aicrg.yml` **at the base commit**; strict built-in default if none exists | normal operation |
| `--policy PATH` | `PATH` **at the base commit**; ERROR if it does not exist there | non-standard file name |
| `--policy-from file --policy PATH` | the filesystem | central policy managed outside the repo (operator-trusted) |

A patch never relaxes the contract it is judged by. If the patch edits the
policy file, the gate reports `policy_modified` (REVIEW_REQUIRED at minimum,
and FAIL if the file is in `protected_paths`), and still applies the base
version.

## Fail-closed parsing

All of these are errors, and the decision is **ERROR**, never PASS:

* missing `version`, or an unsupported one (only `1`)
* unknown keys at any level, including typos like `forbiden_changes`
* duplicate keys (`version: 1` twice)
* wrong types (`allow_new_runtime_dependencies: "no"`, `1` instead of `true`)
* unknown `forbidden_changes` classes or `review_required_surfaces`
* empty `allowed_paths: []` (forbids everything; omit the key instead)
* absolute, backslash, character-class or brace glob patterns
* empty or unparseable commands, duplicate check names, timeouts outside 1..86400 s

`aicrg policy validate review-gate.yaml` checks a file and prints its digest.

## Reference

```yaml
version: 1

# Changed files must match one of these (omit = any path).
allowed_paths: [src/**, tests/**]

# Any change to these paths blocks.
protected_paths: [.github/**, review-gate.yaml]

# Commands executed in a clean checkout of the head commit (source: head).
required_checks:
  - pytest                       # string form: name == command
  - name: types
    command: mypy src            # shlex-split; never run through a shell
    timeout_seconds: 600         # default 900; timeout => ERROR
  - name: lint
    command: ruff check --output-format sarif -o out/ruff.sarif .
    report: {format: sarif, path: out/ruff.sarif}   # sarif|junit|cobertura|lcov|json
    block_levels: [error]          # SARIF/JSON levels that BLOCK; lower levels => REVIEW
    differential: true             # also run on the merge-base (docs/EVIDENCE.md)
    preexisting_failure: review    # fail | review (default) | allow (proven-identical only)
    required: true                 # false => SKIPPED/ERROR/TIMEOUT is advisory, not ERROR
  - name: coverage
    command: python -m pytest -q --cov=app --cov-report=xml:out/cov.xml
    report: {format: cobertura, path: out/cov.xml}
    min_changed_coverage: 0.8      # added production lines executed; below => REVIEW

# Evidence the candidate cannot write (docs/EVIDENCE.md#trusted-evidence).
trusted_evidence:
  - name: auth-contract
    source: base                   # files matching `paths` come from the merge-base
    paths: [trusted_tests/**]
    command: python -m pytest -q -c trusted_tests/pytest.ini --rootdir . --confcutdir trusted_tests trusted_tests
  - name: release-evals
    source: bundle                 # immutable dir/tar; wrong digest => ERROR
    digest: sha256:<64 hex>        # `aicrg bundle digest PATH`
    mount: release_evals
    bundle: /opt/evals/release.tar # default location; --bundle NAME=PATH overrides
    command: python -m pytest -q --confcutdir release_evals release_evals

# Reports produced elsewhere, supplied with --evidence NAME=PATH.
external_evidence:
  - name: codeql
    format: sarif                  # missing report => SKIPPED => ERROR (required by default)

# Changed-code mutation (docs/TEST_POTENCY.md).
test_potency:
  command: python -m pytest -q -x -p no:cacheprovider tests
  paths: [app/**]
  max_mutants: 40
  mutant_timeout_seconds: 120
  total_timeout_seconds: 1800
  on_survivor: review              # review | fail
  on_error: review                 # review | error  (never PASS)

# Change classes that BLOCK. Not listed => REVIEW_REQUIRED (never silent).
# Omit the key to forbid all of them (the default).
forbidden_changes:
  - test_deletion
  - security_check_disablement
  - secret_introduction
  - ci_test_bypass
  - unsafe_execution
  - exception_swallowing
  - golden_data_modification

dependency_policy:
  allow_new_runtime_dependencies: false   # default false
  allow_new_dev_dependencies: true        # default true
  allowed_new_dependencies: [requests]    # pre-approved names (normalised)
  max_new_dependencies: 3                 # default 3; above => BLOCK
  require_pinned_versions: false          # true => new/changed deps must be ==pinned
  allow_direct_url_dependencies: false    # git+/http/path deps

minimum_test_integrity:
  forbid_new_unconditional_skips: true      # skip/skipif(True)/pytest.skip() => BLOCK
  forbid_removed_security_assertions: true  # removed/weakened assertions in security tests => BLOCK
  forbid_assertion_weakening: true          # weakened/vacuous/broadened anywhere => BLOCK

# Surfaces that always need a human, even if everything passes.
review_required_surfaces: [ci, crypto]

# Extra golden/snapshot locations (added to the built-in list).
golden_paths: [tests/data/expected/**]

# Data that intentionally contains bad code (fixtures, corpora). Still subject to
# allowed/protected paths and risk; skipped by content analysers. Workflows and the
# policy file are never excluded.
exclude_from_analysis: [corpus/**]

execution:
  env_passthrough: [DATABASE_URL]   # credential-looking env vars are withheld otherwise
  executor: container               # local (default, trusted-code mode) | container
  container:                        # docs/EXECUTION_SECURITY.md
    image: python:3.12-slim@sha256:<digest>
    runtime: docker                 # docker | podman
    network: none                   # none (default) | enabled
    cpus: 2
    memory_mb: 2048
    pids_limit: 512
    tmpfs_mb: 512
    user: "65534:65534"             # numeric, never 0

# Receipt authenticity required at verify time (docs/RECEIPTS.md).
attestation:
  required: true
  method: github                    # github | ssh
  repository: OWNER/REPO
  signer_workflow: OWNER/REPO/.github/workflows/aicrg-gate.yml
  signer_ref: refs/heads/main

llm_reviewer:                        # optional; see docs/RECEIPTS.md#llm_review
  command: [python, tools/reviewer.py]
  timeout_seconds: 300
  required: false                    # true => reviewer failure is ERROR
  env_passthrough: [ANTHROPIC_API_KEY]   # given to the reviewer only, never to checks
```

## Semantics worth knowing

* **Floors, not switches.** Test-integrity and security findings are at least
  REVIEW_REQUIRED whatever the contract says. The contract only decides which of
  them escalate to FAIL. There is no waiver mechanism in v1; a human resolves
  REVIEW_REQUIRED.
* **Glob semantics.** `*` never crosses `/`. `**` matches zero or more whole
  directories. A pattern without `/` matches the basename at any depth (`*.lock`).
  A trailing `/` means "everything under". A leading `./` anchors the pattern at
  the repository root: `./review-gate.yaml` is only the root file, while
  `review-gate.yaml` also matches `fixtures/x/review-gate.yaml`.
* **High-risk patches need evidence.** If the patch touches a HIGH or CRITICAL
  surface and the contract has no `required_checks`, the gate returns
  REVIEW_REQUIRED (`insufficient_evidence`).
* **The base contract is a floor for execution too.** `execution.executor:
  container` cannot be downgraded from the CLI; an unavailable runtime is ERROR.
* **Evidence names are unique** across `required_checks`, `trusted_evidence`
  and `external_evidence`; report paths must be relative, without `..` or `.git`.
* **Commands run head's code.** If your project is installed in editable mode,
  make sure the check imports from the working directory: for pytest set
  `pythonpath = ["src"]`, or install inside the check command.
* **Digest.** `contract_digest` is SHA-256 over the canonical JSON of the
  *parsed* contract, so formatting and key order do not matter but every semantic
  change does. `raw_digest` covers the file bytes.
