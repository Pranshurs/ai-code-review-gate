# Test potency: do the submitted tests constrain the changed code?

Coverage says a changed line *executed*. It does not say any assertion would
notice if that line were wrong. Test potency asks: **would the submitted tests
detect plausible incorrect versions of the production code this patch
changed?**

```yaml
test_potency:
  command: python -m pytest -q -x -p no:cacheprovider tests
  paths: [app/**]                 # production code eligible for mutation
  max_mutants: 40                 # above this: random sample (seed recorded), status SAMPLED
  mutant_timeout_seconds: 120
  total_timeout_seconds: 1800
  on_survivor: review             # review (default) | fail
  on_error: review                # review (default) | error
```

## How it works

1. Changed production lines: lines the patch *added* in production `.py`
   files matching `paths`. A file named like a test (`test_x.py`, `x_test.py`,
   under `test/`) counts as production when non-test code imports it.
2. First-order mutants are generated **only on those lines**
   (`src/aicrg/potency/mutators.py`): comparison swaps, `and`/`or`, dropped
   `not`, negated conditions, `True`/`False`, numeric `n → n+1`, strings used
   in comparisons or returns, arithmetic swaps, `return x → return None`,
   `raise → pass`. Docstrings, annotations and f-string internals are not
   mutated. Each edit replaces only the exact source span of the node.
3. A mutant whose **compiled bytecode equals the original** is equivalent by
   construction (e.g. a constant in a branch the compiler removes); it is
   recorded and not run.
4. In a clean head checkout, through the contract's executor, the unmutated
   command must pass first (baseline). Then **control mutants** run: the
   file with a dead module-level assignment appended, and, for every mutated
   function, the function with a dead local assignment inserted — identical
   behaviour, different text, AST and bytecode. They must survive; if the
   tests "kill" one, they depend on the code's form (a test pinning the file's
   SHA-256, its AST, or a function's bytecode) and kill counts would mean
   nothing, so potency is ERROR. This is a deterrent, not a proof: tests can
   still fingerprint mutants through other side channels. Then each mutant is written in place, the
   command runs, and the original is restored.
5. Mutant outcome: **killed** (command failed), **killed by timeout**,
   **survived** (command passed), **not run** (budget exhausted).

Example:

```
Changed production lines:     2
Relevant mutants:             7
Killed by submitted tests:    6
Surviving mutants:            1   app/price.py:4  (total // 10) -> (total / 10)

TEST POTENCY: REVIEW_REQUIRED
```

That survivor is real: every test used a multiple of ten, so `20.0 == 20`
held. It is the example in `tests/test_potency.py`.

## Semantics

| status | meaning | decision effect |
|---|---|---|
| `COMPLETE` | every relevant mutant killed | none |
| `SURVIVORS` | ≥1 mutant survived | `test_potency_survivor`: REVIEW (or BLOCK with `on_survivor: fail`) |
| `SAMPLED` | more mutants than `max_mutants`; a random sample (seed recorded in the receipt) was all killed | `test_potency_unavailable` REVIEW: the unsampled behaviour is unmeasured |
| `NO_MUTANTS` | no mutation site on changed production lines | none (nothing to measure) |
| `ERROR` | baseline failed, control mutant killed, a target does not parse, test command could not start, executor unavailable | `test_potency_unavailable` REVIEW, or ERROR with `on_error: error` |
| `TIMEOUT` | total budget exhausted before every mutant ran | as ERROR |

A surviving mutant does **not** prove the implementation is wrong. It proves
the submitted evidence does not pin down that behaviour, so a human should
look (or a stronger test should be added). An unmeasurable result is never
PASS. `# pragma: no mutate` / `# aicrg: no-mutate` on an added line is
honoured but reported as `test_potency_suppressed` (REVIEW): the patch cannot
quietly opt out.

## Why not an existing mutation engine?

mutmut 3.x and cosmic-ray 8.x were evaluated. Both are full frameworks that
mutate whole modules and keep their own configuration and session state in
the target repository; neither selects mutants by diff lines. Potency needs
diff-scoped, deterministic mutant selection that runs through AICRG's
executor boundary, so AICRG ships a small generator (operators only, ~300
lines) rather than a framework. It is first-order and Python-only; for deep
mutation analysis run a full engine as an evidence provider.

## Cost

Potency runs the test command once per mutant. Its cost is
`(1 + mutants) × test-suite time` and is reported separately from gate
overhead in [results/bench.json](results/bench.json). Keep the command
focused (e.g. `-x`, the relevant test directory) and use `max_mutants`.
