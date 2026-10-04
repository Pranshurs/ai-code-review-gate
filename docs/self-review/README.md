# Self-review

`scripts/self_review_challenge.py` makes AICRG review its own changes under its
own [review-gate.yaml](../../review-gate.yaml), read from the base commit. It
then hands the gate a mutant of itself: a throwaway commit that weakens one of
its own invariant tests the way a coding agent might ("fix flaky test"). Finally
it verifies the repository is restored exactly: same HEAD, same index/worktree
status, same diff digest, no leftover worktree, mutant unreachable from any branch.

The mutant change:

```diff
         res = gate()
-        assert res.decision is Decision.FAIL
-        assert "required_check_failed" in codes(res)
+        # flaky on CI runners; accept either outcome
+        assert res.decision in (Decision.FAIL, Decision.PASS)
```

## Run 1: base 53d7d73 → head 0acae1c

| | decision | notes |
|---|---|---|
| self-review | **FAIL** | AICRG found a bug in its own policy: `protected_paths: [review-gate.yaml]` matched the fixture policies under `corpus/` (basename-at-any-depth glob semantics). The CI workflow change was also routed to human review (`review_required_surfaces: [ci]`). |
| mutant | **FAIL** | `assertion_weakened` (strength 3 → 2), `assertion_removed` (review); all 6 required checks still passed on the mutant |
| restoration | exact | |

Files: `run1-self-review-receipt.json`, `run1-mutant-receipt.json`, `run1-challenge.json`.

Fix: the contract language gained `./` root anchoring (commit 4bac21a), and the
policy was changed to `./review-gate.yaml` in a separate commit (9a06ecc) labelled
as a policy change. That change is itself a protected-path modification and needs
the owner's review. A gate cannot approve changes to its own rules.

## Run 2: base 9a06ecc → head b905f90

| | decision | notes |
|---|---|---|
| self-review | **PASS** | all 6 required checks executed in a worktree of b905f90: ruff check, ruff format, mypy, pytest, dev corpus, mutation gate (27/27) |
| mutant | **FAIL** | `assertion_weakened` |
| restoration | exact | |

Files: `self-review-receipt.json`, `mutant-receipt.json`, `challenge.json`.

`aicrg verify-receipt docs/self-review/self-review-receipt.json --head b905f90`
accepts the PASS receipt. It rejects it for any later commit (stale), and rejects
the mutant receipt (decision FAIL).

`main` does not exist in the repository yet, so these runs use explicit base
commits instead of `--base main`.
