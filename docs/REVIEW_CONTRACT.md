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

# Commands executed in a fresh worktree of the head commit.
required_checks:
  - pytest                       # string form: name == command
  - name: types
    command: mypy src            # shlex-split; never run through a shell
    timeout_seconds: 600         # default 900; timeout => ERROR

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
  A trailing `/` means "everything under".
* **High-risk patches need evidence.** If the patch touches a HIGH or CRITICAL
  surface and the contract has no `required_checks`, the gate returns
  REVIEW_REQUIRED (`insufficient_evidence`).
* **Commands run head's code.** If your project is installed in editable mode,
  make sure the check imports from the working directory: for pytest set
  `pythonpath = ["src"]`, or install inside the check command.
* **Digest.** `contract_digest` is SHA-256 over the canonical JSON of the
  *parsed* contract, so formatting and key order do not matter but every semantic
  change does. `raw_digest` covers the file bytes.
