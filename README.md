# AI Code Review Gate

**Independent acceptance evidence for AI-generated code.**

Your coding agent says the patch is done. AICRG checks the patch, the tests, the
security-sensitive changes and the evidence before you merge it.

```
Agent:
  "Fixed the auth bug. All tests pass."

What actually changed:
  ✓ implementation changed
  ✓ tests pass                      (27 passed)
  ✗ security assertion weakened     assert response.status == 401
                                 →  assert response.status != 500

AICRG:
  MERGE BLOCKED
```

Existing tools each answer one question about a patch: is there a known
vulnerability pattern, do types check, does lint pass, did tests exit 0. AICRG
asks whether **the evidence package as a whole** is enough to accept the patch,
and treats the parts a patch can tamper with (its tests, its CI config, its
policy file, its claims) as untrusted inputs, not as proof.

It works the same whether the patch came from Claude Code, Codex, Cursor,
Copilot, another agent, a human, or nobody knows.

> Status: **pre-release, private**. Python-first. Not published to PyPI.
> Read [what a PASS means](docs/THREAT_MODEL.md#what-a-pass-means) and the
> [measured miss rate](#does-it-work) before relying on it.

## Five-minute quickstart

```bash
pip install ai-code-review-gate          # not on PyPI yet: pip install git+<this repo>@<sha>

aicrg check --base origin/main --head HEAD
```

Add a contract to state what evidence you require. Commit it to your main
branch: the gate always reads the contract from the **base** commit, so a patch
cannot relax its own rules.

```yaml
# review-gate.yaml
version: 1
allowed_paths: [src/**, tests/**]
protected_paths: [.github/**, review-gate.yaml]
required_checks:
  - name: tests
    command: python -m pytest -q
  - name: lint
    command: ruff check .
  - name: types
    command: mypy src
dependency_policy:
  allow_new_runtime_dependencies: false
minimum_test_integrity:
  forbid_new_unconditional_skips: true
  forbid_removed_security_assertions: true
```

```
$ aicrg check --base origin/main --head HEAD --policy review-gate.yaml

AI CODE REVIEW GATE

Patch:       7ba21346d615 -> c1fcb93be5f4  (1 files)
Policy:      base:review-gate.yaml
Risk:        CRITICAL  [auth, tests]

Change contract               PASS
Required checks               PASS
Test integrity                FAIL
CI integrity                  PASS
Security regressions          PASS
Dependency policy             PASS
Analysis coverage             PASS
Reviewer model (advisory)     OFF

  ok  tests            0.53s  python -m pytest -q -p no:cacheprovider

BLOCKED

Blocking:
  [assertion_weakened] tests/test_auth.py:13
    test_unauthenticated_request_is_rejected_with_401: assertion on `response.status` weakened (strength 3 -> 1)
    before: assert response.status == 401
    after:  assert response.status != 500

Receipt:
  .aicrg/receipts/c1fcb93be5f432ff061e9e7531c56a582048250b.json
```

Exit codes: `0` PASS · `1` FAIL · `3` REVIEW_REQUIRED · `4` ERROR (the gate could
not complete; never treated as PASS) · `5` receipt rejected.

## What it checks

```
PATCH → PROVENANCE → CONTRACT → RISK SURFACE → EVIDENCE EXECUTED → ADVERSARIAL CHECKS → RECEIPT → DECISION
```

| stage | what happens |
|---|---|
| Provenance | base/head resolved to SHAs once; merge-base, head tree, patch digest, repo identity |
| Contract | typed, fail-closed policy read from the base commit; unknown keys or bad types are ERROR |
| Risk surface | auth, crypto, CI, dependencies, migrations, subprocess, filesystem, network, secrets, tests, validation, concurrency; from paths and the AST of the touched functions |
| Evidence | `required_checks` run in a fresh worktree of the exact head commit, with credential-looking env vars withheld; exit status, timing, output digest recorded |
| Test integrity | removed or weakened assertions, broadened `pytest.raises`, vacuous asserts, new skips/xfail, shrunk `parametrize`, deleted tests, golden-file edits, pytest/coverage/mypy/ruff config loosening ([details](docs/TEST_INTEGRITY.md)) |
| CI integrity | test steps removed, `\|\| true` / `--exit-zero` / `continue-on-error`, disabled jobs, removed scanners, `pull_request_target` added |
| Security regressions | auth checks or decorators removed, `verify=False`, `shell=True` with dynamic input, `pickle`/`eval`, `compare_digest` removed, broad `except: pass`, fail-open handlers, security defaults flipped, secrets |
| Dependencies | new runtime deps vs policy, URL/VCS deps, near-miss names, index changes, lockfile drift |
| Reviewer model | optional, off by default; can only add cited **hypotheses**, at most REVIEW_REQUIRED |
| Receipt | versioned JSON bound to SHAs, patch digest and policy digest; `aicrg verify-receipt` rejects stale or edited receipts |

Linters, type checkers, Bandit, Semgrep, pip-audit and your tests are evidence
providers: list them in `required_checks`. AICRG does not reimplement them.

## Does it work?

Measured on adversarial patch corpora where each bad patch keeps the project's
tests **green** (full method and every miss: [docs/EVALUATION.md](docs/EVALUATION.md)):

| corpus | bad patches blocked | legitimate patches accepted |
|---|---|---|
| held-out v2 (blind, not tuned on) | **28 / 36** (78%) | **11 / 13** |
| held-out v1 (blind, first run) | **25 / 35** (71%) | **10 / 11** |
| dev (written with the detectors; tuning only) | 37 / 37 | 7 / 7 |

**What it misses:** semantic changes with no syntactic trace (a constant
changed from 8 to 6, `startswith` used for path containment, a permission string
swapped), checks missing from *new* code, encoded secrets, narrow exception
suppression, assertions behind environment guards. **False positives:** checks
moved into helpers in other modules, tests consolidated into a parametrized test.

The held-out corpora were written by AI sub-agents working blind to the
implementation. That is weaker independence than human red-teaming.

## The gate checks itself

* **Mutation gate** ([scripts/mutation_gate.py](scripts/mutation_gate.py)): 27
  targeted mutants, each breaking one security-critical invariant (stale HEAD
  accepted, failed command treated as PASS, malformed policy allowed, policy read
  from head, errors becoming PASS, secrets unredacted...). All 27 are killed by
  the test suite.
* **Self-review** ([docs/self-review/](docs/self-review/)): AICRG runs on its own
  changes under its own [review-gate.yaml](review-gate.yaml), then is handed a
  mutant of itself that weakens one of its own invariant tests ("fix flaky
  test"). It blocks the mutant, and the script verifies the repository is
  restored exactly.

## Overhead

Gate only, project tests excluded (4 vCPU x86_64, Python 3.11, git 2.43;
[raw](docs/results/bench.json)):

| patch | p50 | p95 | p99 | n |
|---|---|---|---|---|
| 2 files, 11 changed lines | 62 ms | 78 ms | 83 ms | 100 |
| whole repository as one patch: 308 files, 17.9k lines | 1.76 s | 1.85 s | 1.88 s | 20 |

Policy evaluation is about 0.5 ms p50; sealing and writing the receipt about 1.3 ms
(small) and 9 ms (large). Peak Python heap is 0.3 MiB / 22 MiB. The fixture's own
test suite takes 341 ms p50: that time belongs to the project, not the gate.

## GitHub Actions

```yaml
on: pull_request            # never pull_request_target
permissions:
  contents: read
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with: { fetch-depth: 0, persist-credentials: false }
      - uses: Pranshurs/ai-code-review-gate@<sha>
        with: { policy: review-gate.yaml }
```

Make the job a **required status check**. The receipt is uploaded as an
artifact, and a summary is written to the job page. Read the
[threat boundary](docs/GITHUB_ACTIONS.md#threat-boundary) before running it on
fork PRs.

## What it is not

Not an LLM review bot, not a scanner, not a sandbox, not a merge bot. A PASS
**does not** mean the patch is correct or secure. It means the evidence the
contract requires exists, ran against the exact commit, and was not visibly
weakened by the patch. The receipt digest is tamper-evident, **not signed**.

## Documentation

* [Architecture](docs/ARCHITECTURE.md)
* [Review contract](docs/REVIEW_CONTRACT.md)
* [Test integrity](docs/TEST_INTEGRITY.md)
* [Receipts](docs/RECEIPTS.md)
* [Threat model](docs/THREAT_MODEL.md)
* [Evaluation](docs/EVALUATION.md)
* [GitHub Actions](docs/GITHUB_ACTIONS.md)
* [Ecosystem review](docs/ECOSYSTEM.md)

## Development

```bash
python -m venv .venv && . .venv/bin/activate && pip install -e '.[dev]'
ruff check src tests && mypy && pytest -q
python corpus/run_corpus.py corpus/dev
python scripts/mutation_gate.py
```

This project is developed with AI assistance (Claude Code). That is the point of
it: AI-written code, accepted only on independent, reproducible evidence.

Apache-2.0.
