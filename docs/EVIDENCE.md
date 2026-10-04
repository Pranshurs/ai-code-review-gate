# Evidence: who controls it, how it is collected, how it is judged

The question AICRG asks is not "do the tests pass?" but **"is there enough
evidence, outside the patch's own control, to accept this patch?"** Every
piece of evidence in a receipt records its `source` — who controls its
content — and its `revision` — which code it ran against.

| `source` | content controlled by | contract section |
|---|---|---|
| `head` | the candidate patch | `required_checks` |
| `base` | the base branch (merge-base) | `trusted_evidence` (`source: base`) |
| `bundle` | an immutable, digest-pinned bundle | `trusted_evidence` (`source: bundle`) |
| `external` | another system (e.g. a CodeQL job), handed over by the operator | `external_evidence` |

Contents: [trusted evidence](#trusted-evidence) ·
[evidence providers](#evidence-providers) ·
[differential base/head evidence](#differential-basehead-evidence) ·
[changed-line coverage](#changed-line-coverage) ·
[test potency](TEST_POTENCY.md)

---

## Trusted evidence

A coding agent rewarded for green tests can change the implementation **and**
weaken the visible tests that judge it. The candidate's test run is then
green. Trusted evidence is evidence whose content the patch cannot write.

```yaml
trusted_evidence:
  - name: auth-contract
    source: base                      # files come from the merge-base
    paths: [trusted_tests/auth/**, trusted_tests/pytest.ini]
    command: python -m pytest -q -p no:cacheprovider -c trusted_tests/pytest.ini
             --rootdir . --confcutdir trusted_tests trusted_tests/auth

  - name: release-invariants
    source: bundle                    # an immutable directory or tar archive
    digest: sha256:9f2c…              # aicrg-tree-v2 digest, pinned in the BASE contract
    mount: release_tests              # where it appears in the workspace
    bundle: /opt/evals/release.tar    # default location; --bundle NAME=PATH overrides
    command: python -m pytest -q -p no:cacheprovider --confcutdir release_tests release_tests
```

How it runs:

1. A fresh checkout of the **candidate head** is made — one per trusted spec.
2. `source: base`: every file matching `paths` is made **identical to the
   base tip** (the branch the patch is merged into, not the merge-base: a
   branch cut from an old base must not be judged by old trusted tests): candidate edits are overwritten, candidate deletions are
   restored, files the candidate *added* under those paths (e.g. a
   `conftest.py` that marks failures as passed) are removed, and a directory
   the candidate replaced with a symlink is replaced by a real directory.
   `source: bundle`: the bundle is read, its digest recomputed and compared
   with the pin; on mismatch the gate reports ERROR and the bundle is never
   used. The `mount` subtree is replaced by the bundle's files.
3. The trusted command runs against the candidate implementation through
   the same executor as everything else. With the container executor the
   **entire workspace is mounted read-only** for trusted runs (only the
   check's own report directory, if it has one, is writable), so candidate
   code cannot create, edit or delete anything the run will read; with the local executor they are made non-writable on a
   best-effort basis (same-user code can undo that). After the run, every
   trusted file is compared with the trusted content and new files under
   trusted paths are detected; a change makes that run **ERROR**, whatever
   its exit status.
4. A failure is `trusted_evidence_failed` (BLOCK). A patch that touches
   trusted paths gets `trusted_evidence_modified` (REVIEW) even though its
   edits were discarded, so the attempt is visible.

The receipt lists, per overlay, its digest, the number of trusted files, and
which candidate files were replaced or removed.

**Golden/evaluation data** works the same way: put expected outputs under a
`source: base` path or in a bundle, and the candidate cannot "bless" its own
regression by regenerating them.

**Bundle digests** (`aicrg-tree-v2`): SHA-256 over a canonical JSON manifest
`{"format": "aicrg-tree-v2", "entries": [[path, mode, sha256(content)], ...]}`
sorted by path, mode `100644` or `100755`. JSON encoding makes the manifest
injective: no path can imitate another entry (v1's plain-text lines could be
forged with a newline inside a member name — found in the cold security
review and fixed before release). Directories and tar archives with the same
files have the same digest. Symlinks, special files, absolute paths, `..`
and control characters in names are rejected.

### Limits — what the candidate still controls

The trusted command imports the candidate's code. Candidate code can:

* detect that it is under test and behave differently;
* patch the test runner from outside the trusted paths (a root `conftest.py`,
  `sitecustomize.py`, a pytest plugin entry point, `pyproject.toml` pytest
  options). Mitigate with `-c <trusted ini>` (ignores the candidate's
  pytest configuration), `--confcutdir <trusted dir>` (stops conftest
  discovery above it — tested in `test_root_conftest_cannot_reach_trusted_run`),
  `-p no:<plugin>`, and by listing runner configuration in `paths`.

**Make sure the trusted command imports the code under review.** With
`pytest -c <ini>`, the ini's `pythonpath` is resolved relative to the ini
file, not the repository root. If the project is also installed in the
environment (an editable install is common), a wrong `pythonpath` makes the
trusted tests import the *installed* copy and silently judge the wrong code.
AICRG's own `tests/trusted.ini` hit exactly this during development and uses
`pythonpath = ../src ..` for that reason. Check once with a test that asserts
`yourpkg.__file__` is inside the workspace.

Patch-level analysis still reports conftest, collection-hook and test
configuration changes. Trusted evidence moves the *assertions* out of the
patch's reach; it does not make the code under test honest.

---

## Evidence providers

AICRG does not reimplement scanners. It runs, or accepts the output of,
purpose-built tools and normalises their reports.

```yaml
required_checks:
  - name: semgrep
    command: semgrep scan --config p/ci --sarif --output out/semgrep.sarif
    report: {format: sarif, path: out/semgrep.sarif}
    block_levels: [error]            # error-level results BLOCK; others need REVIEW

external_evidence:                  # produced elsewhere; --evidence codeql=PATH
  - name: codeql
    format: sarif
```

External reports must come from **outside the evaluated checkout** (a file the
patch committed is refused), and a SARIF report that records
`versionControlProvenance.revisionId` must name the head (or the CI commit)
being judged. A report without that field — any SARIF that omits it, and every
JUnit/coverage/JSON report — is **not bound** to a commit: AICRG trusts the
operator who supplied it. Set `require_revision: true` on the entry to refuse
unbound reports (CodeQL records the revision; many tools do not).

| format | typical providers |
|---|---|
| `sarif` | CodeQL, Semgrep, Bandit (`-f sarif`), Ruff (`--output-format sarif`), Gitleaks / TruffleHog (SARIF), osv-scanner, mypy via a SARIF adapter |
| `junit` | pytest (`--junitxml`), most test runners |
| `cobertura` | coverage.py (`coverage xml`) |
| `lcov` | `coverage lcov`, lcov, JS tooling |
| `json` | `aicrg.evidence/v1` — any tool via a small adapter |

`aicrg.evidence/v1`:

```json
{"schema": "aicrg.evidence/v1", "status": "findings",
 "findings": [{"id": "dep:requests:CVE-2024-35195", "level": "error",
               "message": "...", "file": "requirements.txt", "line": 3}]}
```

Statuses and what they do to the decision:

| status | meaning | required item | optional item (`required: false`) |
|---|---|---|---|
| `COMPLETE` | ran, nothing that matters | — | — |
| `FINDINGS` | ran, reported failures/findings | BLOCK at `block_levels` (every failing JUnit test blocks), REVIEW below | same |
| `SKIPPED` | produced no evidence (no tests collected, all skipped, empty SARIF, external report not supplied) | **ERROR** | advisory |
| `ERROR` | tool failed; report missing, malformed, symlinked, pre-planted, DTD/entity XML, SARIF `executionSuccessful: false`, tool exit not in {0, 1} | **ERROR** | advisory |
| `TIMEOUT` | killed at `timeout_seconds` | **ERROR** | advisory |

A tool that exits 1 but writes a clean report is treated as FINDINGS — a
contradiction is not trusted as "clean".

Delegating detection matters. Held-out v2 missed a base64-encoded secret;
another home-grown regex would be the wrong fix. A secret scanner run as a
SARIF provider (Gitleaks, TruffleHog) is the right one, and AICRG makes its
absence or failure visible instead of silent.

---

## Differential base/head evidence

```yaml
required_checks:
  - name: lint
    command: ruff check --output-format sarif -o out/ruff.sarif .
    report: {format: sarif, path: out/ruff.sarif}
    differential: true
    preexisting_failure: review      # fail | review (default) | allow
```

A differential check also runs on a clean checkout of the **merge-base**.

| base | head | classification | effect |
|---|---|---|---|
| pass | pass | `UNCHANGED_PASS` | none |
| fail | pass | `FIXED_FAILURE` | none |
| pass | fail | `NEW_REGRESSION` | BLOCK |
| fail | fail, every head failure identity already failed on base | `PRE_EXISTING_FAILURE` | `fail` → BLOCK, `review` → REVIEW, `allow` → advisory |
| fail | fail, head has new identities | `NEW_REGRESSION` | BLOCK |
| fail | fail, no structured report to compare | `BOTH_FAIL_UNCOMPARED` | `fail` → BLOCK, otherwise REVIEW (`allow` does not apply: identity is unproven) |
| error | fail | `BASE_UNAVAILABLE` | BLOCK (the head failure stands) |

Failure identities come from the report: JUnit `classname::name`; SARIF
`ruleId|file|fingerprint` (or message), deliberately without line numbers so
an unchanged finding that moved is still the same finding. They are compared
as **multisets**: a second occurrence of an identical finding is new.

`allow` never means "clean": the receipt keeps both runs, their statuses and
the classification, and the finding stays in the receipt as advisory.

---

## Changed-line coverage

```yaml
  - name: coverage
    command: python -m pytest -q --cov=app --cov-report=xml:out/cov.xml
    report: {format: cobertura, path: out/cov.xml}
    min_changed_coverage: 0.9
```

Coverage over the patch's **added production lines** (non-test Python files).
A changed file missing from the report counts as uncovered. Below the
threshold: `changed_code_coverage_low` (REVIEW). Coverage shows a line ran,
not that anything checked it; see [TEST_POTENCY.md](TEST_POTENCY.md).
