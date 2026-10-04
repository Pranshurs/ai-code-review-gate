# Contributing

## Ground rules

1. **Every detector change needs a corpus case.** Add a bad case (and, where a
   false positive is plausible, a legitimate case) to `corpus/dev/`, then make it pass.
2. **Never tune on held-out corpora.** `corpus/heldout*` are evaluation sets. If a
   change is motivated by a held-out miss, say so in the commit message, mark the
   set as contaminated in `docs/EVALUATION.md`, and add a new untouched set before
   claiming improved numbers.
3. **Security-critical invariants need a mutant.** If you add an invariant (a
   condition that must never become PASS), add a mutant to
   `scripts/mutation_gate.py` and a test that kills it.
4. **Fail closed.** New contract keys are typed and validated; unknown values are
   errors. New stages run inside `gate._Run.stage` so exceptions become ERROR.

## Checks

```bash
pip install -e '.[dev]'
ruff check src tests corpus/run_corpus.py scripts
ruff format --check src tests corpus/run_corpus.py scripts
mypy
pytest -q
python corpus/run_corpus.py corpus/dev
python scripts/mutation_gate.py
```

The repository's own `review-gate.yaml` runs the same checks when AICRG
reviews its pull requests.

## AI-assisted contributions

Welcome. They are judged by the same evidence as everything else, including by
this gate.
