# Real-world corpus (frozen)

Purpose: evaluate AICRG on real public-repository patches, as a check separate from the synthetic dev/heldout corpora.
`manifest.yaml` pins 37 cases by repository URL and commit SHA; schema `aicrg.realworld/v1`.

## What the patches are
- `derivation: upstream`: a real, human-authored upstream commit (`base` = its first parent, `head` = the commit).
- `derivation: inverted-fix`: the evaluated patch is `git revert --no-edit <fix_commit>` applied on top of
  `fix_commit`, i.e. a mechanical reversal of a real security fix or CI-hardening commit ("an agent reintroduces
  the vulnerability"). These reversals are not human-authored code, and they also revert any tests/docs the fix added.

## Labels
Labels and expectations (`bad`, `category`, `expect_strict`, `acceptable`, rationale) were assigned by an AI agent
(Claude, Sonnet sub-agent) before any tool was run on the cases. This is NOT a human-labelled corpus. Do not edit
expectations after running a tool.

## Composition
- 16 inverted security fixes (credential leak x3, path handling x4, auth/JWT/debugger x3, TLS verification,
  command injection, deserialization, permission, exception/fail-open, dependency integrity)
- 4 inverted CI-hardening commits (token permissions x2, SHA pinning, persist-credentials)
- 5 real upstream test removals/skips (expected REVIEW_REQUIRED; may be legitimate in context)
- 10 position-selected legitimate commits plus 2 keyword-selected ambiguous CI commits (`bad: false`)
Repos: requests, urllib3, scrapy, pip, tornado, starlette, setuptools, virtualenv, pyyaml, wheel, python-jose,
pyjwt, werkzeug, flask, click.

## Selection rules
See `selection_rules` in the manifest. In short: security/CI fixes were found by keyword search of commit logs and
hand-picked after reading diffs; the legitimate group uses a fixed-position rule (repos x start dates 2024-03-01
and 2024-09-01, first single-parent commit in first-parent order with author date on/after the date that changes a
`.py` file, <= 1500 changed lines).

## Licensing
Only permissively licensed upstreams (MIT, BSD-3-Clause, Apache-2.0) are used; license is recorded per case. Paramiko
was excluded (LGPL). We pin URLs and SHAs only; no third-party code is vendored here. Runners must fetch the repos
themselves.

## Limitations
- Inverted fixes are mechanically derived; a reversal is not a patch a real agent wrote, and it can be easier or
  harder to detect than a natural regression.
- Real-world test-removal/skip/CI examples may be legitimate maintenance in context; their labels reflect "a human
  should look", not proven harm. Two ambiguous CI commits are labelled `bad: false` with REVIEW_REQUIRED preferred.
- The legitimate group includes trivial commits (version bump, 2-line typing fixes) by design of the fixed-position
  rule, and RW26 touches TLS context handling (a later-reworked perf change), so it tolerates REVIEW_REQUIRED.
- Security-fix commits were hand-picked from search hits, so the set is not a random sample. Several advisory IDs come
  from commit messages; a few (e.g. CVE-2024-35195, CVE-2024-34069, CVE-2024-37891) were recalled from memory and the
  commit contents, not independently re-verified against the advisory databases. Fixes with no known advisory
  carry `advisory: null`.
- Small sample (37) with 15 repos; no confidence intervals should be inferred from it.
- No ERROR outcome is ever expected. Categories not covered by real cases: XML parsing (no suitable small
  permissive fix found).
