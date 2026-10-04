# Gate receipts

Every `aicrg check` writes a receipt: `.aicrg/receipts/<head-sha>.json` by default,
or `--receipt PATH`. It records exactly what was evaluated, under which rules,
with what evidence, and what was decided.

## Schema `aicrg.receipt/v1`

| field | content |
|---|---|
| `schema` | `"aicrg.receipt/v1"` |
| `gate` | `{name, version}` |
| `decision` | `PASS` \| `FAIL` \| `REVIEW_REQUIRED` \| `ERROR` |
| `reasons` | ordered human-readable reasons (blocking, then errors, then review) |
| `subject.repository` | `{remote (credentials stripped), root_commits}` |
| `subject.base_ref` / `head_ref` | what the user typed |
| `subject.base` / `merge_base` / `head` / `head_tree` | full SHAs |
| `subject.patch_digest` | `sha256:` of the canonical `git diff --binary --full-index` merge_base..head |
| `subject.files` | per file: status, old/new path, added/removed line counts, binary |
| `subject.working_tree_dirty` | uncommitted changes existed and were **not** evaluated |
| `subject.files_excluded_from_analysis` | count, if `exclude_from_analysis` matched |
| `policy` | `{source, repo_path, raw_digest, contract_digest, contract}` |
| `risk` | `{level, surfaces, evidence[{surface, file, reason}]}` |
| `sections` | per area: PASS / FAIL / REVIEW / ERROR / NONE / OFF |
| `checks[]` | `{name, argv, status, exit_code, started_at, finished_at, duration_ms, output_sha256, output_tail, reason, tool_version}` |
| `findings[]` | `{code, category, severity, kind, message, file, line, before, after, provider}` |
| `summary` | counts; `deterministic_failures`, `heuristic_failures` (codes) |
| `test_integrity` | result + test/assertion counts before and after |
| `dependencies[]` | `{change, ecosystem, name, kind, before, after, source}` |
| `llm_review` | `{status, provider, model, model_version, request_sha256, hypotheses, discarded_uncited, error}` |
| `errors[]` | `{stage, message}`; any entry without a blocking finding makes the decision ERROR |
| `environment` | python, platform, machine, git, aicrg, `env_vars_withheld_from_checks` |
| `timestamps`, `timings_ms` | wall-clock data (not deterministic) |
| `receipt_digest` | `sha256:` over the canonical JSON of everything else |

Canonical JSON: UTF-8, sorted keys, `(",", ":")` separators, no NaN.

Secrets matched by the secret detector are redacted (`AKIA…[20 chars redacted]`)
and check output tails are scrubbed for common token formats before they are
written. The full output is represented only by `output_sha256`.

## Verifying a receipt

```
aicrg verify-receipt .aicrg/receipts/<sha>.json [--head HEAD] [--base origin/main]
```

It is rejected (exit 5) when any of these hold:

| check | catches |
|---|---|
| schema unsupported | unknown format |
| `receipt_digest` mismatch | naive edits to any field |
| decision ≠ PASS (unless `--allow-non-pass`) | using a FAIL/REVIEW receipt as approval |
| gate version ≠ verifier version | rules changed between evaluation and merge |
| `head` ≠ current `--head` | **stale receipt: new commits after evaluation** |
| root commits differ | receipt from another repository |
| recomputed patch digest ≠ recorded | forged subject with a recomputed digest |
| with `--base`: base tip moved | merge result was never evaluated |
| with `--base`: base contract digest changed | policy tightened since evaluation |

## What the digest is not

`receipt_digest` is **not a signature**. Anyone who can write the file can
recompute it, so it detects accidents and naive tampering only. For
authenticity, attest the receipt where it is produced, for example with GitHub
artifact attestations (`actions/attest`) or Sigstore `cosign attest`, using the
receipt as an in-toto predicate whose subject is the head commit. This is planned
and not implemented; see docs/THREAT_MODEL.md (#9).
