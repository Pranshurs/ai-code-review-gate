# AI Code Review Gate

**Independent acceptance evidence for AI-generated patches.**

Your coding agent says the patch is finished. AICRG verifies the exact patch,
its tests, trusted evidence the patch cannot touch, security-sensitive changes
and the required checks — before you accept it.

```
Agent:                  "Fixed the authorization bug. Tests pass."

Candidate tests:        PASS
What changed:           implementation changed
                        authorization test weakened   is False  ->  in (True, False)
Trusted base test:      FAIL   (owned by the base branch, run against the candidate code)
Changed-code mutants:   6 of 6 survive the submitted tests

AICRG:                  MERGE BLOCKED
```

That is real output, reproducible with `python scripts/demo.py`.

The core question is not "did the tests pass?" but:

> **Can a coding agent manipulate the tests, evaluator, CI or evidence used to
> judge its own patch?**

AICRG makes that materially harder by moving critical acceptance evidence
outside the patch's authority:

* the **review contract** is read from the base commit, never the patch;
* **trusted evidence** (base-owned tests, or an immutable digest-pinned bundle)
  runs against the candidate code whatever the patch did to its own tests;
* evidence runs in a **clean checkout** of the exact commit, optionally inside
  an **isolated container**, never the developer's working tree;
* **differential** base/head runs separate new regressions from pre-existing
  failures without calling either "clean";
* **test potency** checks whether the submitted tests would notice wrong
  versions of the changed code;
* results from **specialist scanners** (CodeQL, Semgrep, Bandit, secret
  scanners, test runners, coverage) are ingested, and a required one that is
  skipped or fails is ERROR, never PASS;
* a versioned **receipt** binds decision, commits, patch, policy and evidence;
  verification rejects stale receipts and, when required, unsigned ones
  (GitHub artifact attestations / Sigstore, or SSH signatures);
* **`aicrg doctor`** checks whether a pull request could disable its own gate.

It is not "AI that reviews AI code". An optional reviewer model can raise
hypotheses (at most REVIEW_REQUIRED); it can never turn a deterministic FAIL or
ERROR into PASS. It works the same whether the patch came from Claude Code,
Codex, Cursor, Copilot, another agent, or a human.

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
| Evidence | `required_checks` run in a clean checkout of the exact head commit through an executor (`local` = trusted-code mode; `container` = unprivileged, no network, no host env, resource-limited); exit status, timing, output digest, provider status recorded ([execution security](docs/EXECUTION_SECURITY.md)) |
| Trusted evidence | base-owned paths or a digest-pinned bundle overlaid on the head; candidate edits, deletions, additions and symlink tricks under those paths are discarded ([evidence](docs/EVIDENCE.md#trusted-evidence)) |
| Providers | SARIF / JUnit / Cobertura / LCOV / JSON reports from CodeQL, Semgrep, Bandit, Ruff, secret scanners, pytest, coverage; external reports via `--evidence`; required + SKIPPED/ERROR/TIMEOUT ⇒ ERROR |
| Differential | checks marked `differential` also run on the merge-base: NEW_REGRESSION vs PRE_EXISTING_FAILURE (proven by failure identities) vs FIXED_FAILURE |
| Test potency | diff-scoped mutants of changed production lines; surviving mutants ⇒ REVIEW ([details](docs/TEST_POTENCY.md)) |
| Test integrity | removed or weakened assertions, broadened `pytest.raises`, vacuous asserts, new skips/xfail, shrunk `parametrize`, deleted tests, golden-file edits, pytest/coverage/mypy/ruff config loosening ([details](docs/TEST_INTEGRITY.md)) |
| CI integrity | test steps removed, `\|\| true` / `--exit-zero` / `continue-on-error`, disabled jobs, removed scanners, `pull_request_target` added |
| Security regressions | auth checks or decorators removed, `verify=False`, `shell=True` with dynamic input, `pickle`/`eval`, `compare_digest` removed, broad `except: pass`, fail-open handlers, security defaults flipped, secrets |
| Dependencies | new runtime deps vs policy, URL/VCS deps, near-miss names, index changes, lockfile drift |
| Reviewer model | optional, off by default; can only add cited **hypotheses**, at most REVIEW_REQUIRED |
| Receipt | versioned JSON bound to SHAs, patch digest, policy digest and evidence; `aicrg verify-receipt` reports INTEGRITY and AUTHENTICITY separately, rejects stale/edited receipts, and unsigned ones when attestation is required ([receipts](docs/RECEIPTS.md)) |
| Doctor | `aicrg doctor [--github]`: missing or masked gate, pwn-request patterns, broad tokens, unpinned actions, secrets in the gate job, gate not a required check; UNKNOWN is never PASS |

Linters, type checkers, Bandit, Semgrep, CodeQL, secret scanners, pip-audit
and your tests are evidence providers. AICRG does not reimplement them.

## Does it work?

Measured on adversarial patch corpora where each bad patch keeps the project's
tests **green**, plus a real-world track (full method and every miss:
[docs/EVALUATION.md](docs/EVALUATION.md)):

| corpus | bad patches blocked | legitimate patches accepted |
|---|---|---|
| held-out v2 (blind, not tuned on) | **28 / 36** (78%) | **11 / 13** |
| held-out v1 (blind, first run) | **25 / 35** (71%) | **10 / 11** |
| real-world: 37 pinned upstream patches, static layer only | **18 / 25** | **12 / 12** |
| dev (written with the detectors; tuning only) | 37 / 37 | 7 / 7 |

The real-world track reverses 16 real security fixes and 4 CI-hardening
commits, and includes real test removals and 12 ordinary upstream commits. Most
of its detections come from the reversal also deleting the fix's regression
test; reversed CI hardening (removed `permissions:`, unpinned actions) was
missed 0/4. Against tampercheck 0.1.1 and tamperguard 0.2.0 on identical diffs
(verification-tampering scope): held-out v2 17/21 vs 4/21 and 5/21 (7/21 with
tamperguard's review verdicts); real-world 4/10 vs 2/10 and 0/10 (2/10).

**What it misses:** semantic changes with no syntactic trace (a constant
changed from 8 to 6, `startswith` used for path containment, a permission string
swapped), checks missing from *new* code, encoded secrets, narrow exception
suppression, assertions behind environment guards. These are the cases the
structural layers target instead of more pattern rules: in a post-hoc
experiment, test potency turned 3 of the 8 held-out v2 misses into
REVIEW_REQUIRED; trusted evidence and a secret scanner as a required provider
cover others. **False positives:** checks moved into helpers in other modules,
tests consolidated into a parametrized test (both still FAIL rather than
REVIEW_REQUIRED; an open design decision).

All corpora were written or labelled by AI agents (the real-world patches are
human-authored upstream code, the labels are not). A human-labelled held-out
corpus is still pending.

## The gate checks itself

* **Mutation gate** ([scripts/mutation_gate.py](scripts/mutation_gate.py)): 76
  targeted mutants, each breaking one security-critical invariant: stale HEAD
  accepted, failed command treated as PASS, policy read from head, trusted
  evidence read from the candidate, bundle digest ignored, surviving mutant
  treated as PASS, provider SKIPPED/ERROR treated as PASS, new regression
  hidden as pre-existing, container downgraded to local, network or host env
  leaking into the container, unsigned receipt accepted when attestation is
  required, attestation for the wrong commit or from a PR-ref workflow,
  doctor missing a disabled gate, an unrelated CI commit accepted as evidence
  for the head, and one mutant per fix from the security review... All 76 are
  killed.
* **Cold security review** ([docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md)):
  an independent reviewer found 1 BLOCKER and 9 HIGH issues, then 3 more HIGH
  residuals while re-verifying the fixes; every one was reproduced, fixed and
  pinned by a regression test.
* **Self-review** ([docs/self-review/](docs/self-review/)): AICRG reviews its own
  changes under its own [review-gate.yaml](review-gate.yaml), then is handed 18
  adversarial copies of itself (weakened test, deleted trusted evidence, wrong
  bundle digest, manipulated, resealed, re-subjected, unsigned or attacker-signed
  receipt, skipped/erroring provider, moved head, weakened or disabled gate job,
  container downgraded to local, a report bound to an unrelated CI commit). Each
  is blocked; positive controls (an allowed-key signature, a report bound to the
  head) are accepted; the repository is verified to be restored exactly. The
  latest full-range self-review is **FAIL**: the gate blocked test changes made
  in the 0.2 continuation, which await owner review (run 3).

## Overhead

Measured at commit 2f3b70f (production code identical to dac57d0), clean tree,
4 vCPU x86_64, Python 3.12.3, git 2.43, `python scripts/bench.py -n 100`
([raw](docs/results/bench.json)). Each row is measured separately; none is folded
into another.

| what | p50 | p95 | p99 | n |
|---|---|---|---|---|
| gate only, 2 files / 11 changed lines | 96 ms | 111 ms | 118 ms | 100 |
| gate only, whole repository as one patch (524 files, 50k lines) | 14.4 s | 15.0 s | 15.3 s | 20 |
| target project's own test suite (belongs to the project) | 341 ms | 391 ms | 399 ms | 10 |
| + one trivial check, head checkout, local executor (evidence stage) | 50 ms | 59 ms | 61 ms | 20 |
| + the same as base-owned trusted evidence (evidence stage) | 84 ms | 92 ms | 93 ms | 20 |
| + the same in the container executor (evidence stage) | 779 ms | 801 ms | 801 ms | 5 |
| + required external SARIF provider, empty (evidence stage) | 1.1 ms | 1.7 ms | 1.8 ms | 20 |
| + required external SARIF provider, 1000 results (evidence stage) | 12 ms | 21 ms | 21 ms | 20 |
| verify-receipt (integrity, staleness, patch digest) | 16 ms | 19 ms | 20 ms | 20 |
| SSH-sign a receipt | 6 ms | 9 ms | 9 ms | 20 |
| verify-receipt with SSH signature | 26 ms | 28 ms | 30 ms | 20 |
| test potency, 3 changed lines, 5 mutants + controls, fixture suite | 2.9 s | 3.0 s | 3.0 s | 3 |

Policy evaluation is about 0.6 ms p50; sealing and writing the receipt about
1.3 ms (small) and 12 ms (large). Test potency is deliberately expensive: about
one target-suite run per mutant (here ~480 ms each); its p95/p99 at n=3 are not
meaningful. GitHub artifact-attestation verification (`gh attestation verify`)
needs the attestation service and is not benchmarked.

Known cost: the large case is superlinear. 10.5 s of its 14.4 s is the security
stage, where the check that a test-named module is used by production code
(security-review fixes F7/N3) rescans production files for every test-named file
without caching. It cannot turn a decision into PASS (a slow run times out to
ERROR), but large patches pay for it; a memoised index is a follow-up. The 0.1
release measured 62 ms / 1.76 s (308 files) on Python 3.11 with fewer analyses;
the difference is not attributed to a single cause.

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

Make the job a **required status check**, preferably from a ruleset-required
workflow the PR cannot edit. The receipt is uploaded as an artifact. Sign it in
a **separate job** that runs no candidate code
([example](docs/examples/aicrg-gate-attested.yml)), and run `aicrg doctor`.
Read the [threat boundary](docs/GITHUB_ACTIONS.md#threat-boundary) before
running it on fork PRs.

## What it is not

Not an LLM review bot, not a scanner, not a merge bot. The container executor
is isolation, not a guarantee against kernel or runtime escape. A PASS **does
not** mean the patch is correct or secure, and AICRG does not catch all AI bugs.
It means the evidence the contract requires exists, ran against the exact
commit (trusted parts of it outside the patch's control), and was not visibly
weakened by the patch. Receipts are tamper-evident by digest; they are
authentic only when attested and verified with a pinned signer.

## Documentation

* [Architecture](docs/ARCHITECTURE.md)
* [Review contract](docs/REVIEW_CONTRACT.md)
* [Test integrity](docs/TEST_INTEGRITY.md)
* [Evidence: trusted evidence, providers, differential runs](docs/EVIDENCE.md)
* [Test potency](docs/TEST_POTENCY.md)
* [Execution security](docs/EXECUTION_SECURITY.md)
* [Receipts and attestations](docs/RECEIPTS.md)
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
