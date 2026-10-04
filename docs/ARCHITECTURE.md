# Architecture

```
            aicrg check --base B --head H [--policy P]
                              │
 ┌────────────────────────────▼─────────────────────────────┐
 │ 1. Provenance   git/repo.py, git/diff.py                  │  B, H → full SHAs (once)
 │                 merge-base, head tree, repo identity,     │  canonical diff → patch digest
 │                 changed files + added/removed lines       │
 ├───────────────────────────────────────────────────────────┤
 │ 2. Contract     policy/loader.py, policy/contract.py      │  read from BASE commit
 │                 strict typed parse, fail closed            │  → contract digest
 ├───────────────────────────────────────────────────────────┤
 │ 3. Risk         risk/surfaces.py                          │  path rules + AST of the
 │                 auth, crypto, ci, deps, subprocess, ...    │  touched functions (both sides)
 ├───────────────────────────────────────────────────────────┤
 │ 4. Analysis     contract rules        gate.py             │
 │   (diff-aware,  test integrity        testsafety/         │  every analyser compares
 │    base vs head) test/checker config  testsafety/config   │  BASE vs HEAD and reports
 │                 CI workflows          testsafety/ci       │  only what the patch changed
 │                 security regressions  security/           │
 │                 secrets               security/secrets    │
 │                 dependency delta      dependencies/       │
 ├───────────────────────────────────────────────────────────┤
 │ 5. Evidence     evidence/workspace.py, commands.py        │  fresh worktree of H;
 │                 required_checks executed, recorded         │  FAIL vs ERROR distinguished
 ├───────────────────────────────────────────────────────────┤
 │ 6. Reviewer     llm/reviewer.py (optional)                │  cited HYPOTHESES only,
 │                                                            │  ≤ REVIEW_REQUIRED
 ├───────────────────────────────────────────────────────────┤
 │ 7. Decision     gate.decide()                             │  BLOCK→FAIL; error→ERROR;
 │                                                            │  REVIEW→REVIEW_REQUIRED; PASS
 ├───────────────────────────────────────────────────────────┤
 │ 8. Receipt      receipt/receipt.py, receipt/verify.py     │  canonical JSON + digest;
 │                                                            │  verify-receipt for staleness
 └───────────────────────────────────────────────────────────┘
```

## Core types

| Concept | Where | Notes |
|---|---|---|
| RepositorySnapshot | `git.Repo` + `subject` in the receipt | SHAs resolved once; every later read uses SHAs, never refs |
| Patch | `git.diff.Patch`, `FileChange` | status (A/M/D/R), old/new path, added/removed lines with numbers, digest |
| ReviewContract | `policy.contract.ReviewContract` | frozen dataclass; `digest()` over canonical JSON |
| RiskSurface | `risk.surfaces.RiskAssessment` | level = max surface weight; each hit carries its reason |
| EvidenceProvider | analysers + `evidence.commands.run_check` + `llm.reviewer` | each returns findings / check results; none decides |
| Finding | `model.Finding` | code, category, severity (block/review/advisory), kind (deterministic/heuristic/hypothesis) |
| GateDecision | `model.Decision` | PASS / FAIL / REVIEW_REQUIRED / ERROR |
| GateReceipt | `receipt.receipt` | `aicrg.receipt/v1`, sealed with `receipt_digest` |

## Design rules

1. **Diff-aware, not state-aware.** Analysers compare base and head. A pre-existing
   `verify=False` is not reported; a new one is. Absolute scanning is delegated to
   Bandit/Semgrep/CodeQL run as `required_checks`.
2. **The rule registry is the single source of severity.** `rules.py` lists every
   finding code with its category, kind, and severity source (fixed, a forbidden change
   class, or a named contract field). `aicrg rules` prints it.
3. **No exception path leads to PASS.** `gate._Run.stage` turns any analyser exception
   into a `GateError`; `decide()` maps errors to ERROR unless a BLOCK already exists.
   The CLI's last-resort handler exits 4 (ERROR).
4. **Untrusted text stays data.** File names, test output and reviewer text are
   sanitised when rendered; reviewer output can only append hypotheses.
5. **Determinism.** Findings are sorted; receipts are canonical JSON. Two runs on the
   same inputs differ only in `timestamps`, `timings_ms` and the digest that covers them
   (tested in `test_receipt_digest_is_deterministic_for_same_inputs`).

## Language scope

Python is analysed at AST level. Paths, CI workflows, dependency manifests
(pyproject, requirements, setup.cfg, Pipfile, package.json), secrets, policy and
evidence execution are language-agnostic. Adding a language means adding an
assertion extractor (`testsafety/assertions.py` equivalent) and a facts extractor
(`security/regressions.py` equivalent); nothing else assumes Python. TypeScript, Go,
Java and Rust are **not** analysed today.

## Package layout

```
src/aicrg/
  cli.py            argparse CLI; exit codes 0/1/3/4/5
  gate.py           orchestration, decision, receipt assembly
  model.py          value types
  rules.py          finding registry
  globmatch.py      explicit ** semantics
  git/              provenance and patch extraction
  policy/           review contract
  analysis/         shared AST helpers and cached patch view
  risk/             surface classification
  testsafety/       assertions, test integrity, config, CI workflows
  security/         regressions, secrets
  dependencies/     manifests, delta
  evidence/         worktree, command execution
  llm/              optional reviewer adapter
  receipt/          sealing, verification
  render.py         text and Markdown output
```
