# Ecosystem review

Status: draft, accessed 2026-10-04. Scope: what existing tools do relative to `aicrg`, an acceptance gate for patches (base..head) that binds a decision to SHAs, patch digest and policy digest.

Sourcing note. Several primary documentation hosts (docs.github.com, semgrep.dev, docs.sonarsource.com, bandit.readthedocs.io, danger.systems, slsa.dev, arxiv.org) were blocked by the research environment's egress proxy. For those, facts come from search-result excerpts of the official pages or from project READMEs, and are marked `[search]`. Items marked `[unverified]` could not be confirmed from any consulted page. Vendor-comparison blogs were used only for product descriptions, never for performance claims.

## 1. Summary

- Mature scanners (CodeQL, Semgrep, Bandit, Ruff, mypy, pyright, pip-audit) answer one question each about code or dependency state. Several have a "new findings only" mode (CodeQL PR alerts, Semgrep baseline, reviewdog diff filter, Sonar new code). None of them ask whether the evidence for a patch is sufficient.
- Quality gates (SonarQube/SonarCloud) are the closest incumbent concept. Their default "Sonar way" conditions are: no new issues, new hotspots reviewed, new-code coverage >= 80%, new-code duplication <= 3% `[search]`. They measure the new code, not whether tests or CI were weakened.
- Test tampering by coding agents is documented as a real failure mode in recent research (changing tests, fixtures, snapshots, golden files, skips, CI config) `[search]`. Benchmarks such as SWE-bench are described as vulnerable because patch-modified files are trusted `[search]`.
- Tools that look at test weakening in diffs exist: PyPI packages `tampercheck` (0.1.1, Apache-2.0) and `tamperguard` (0.2.0, MIT). Their wheels were downloaded and read for this review (see section 6a). Both are regex/line-based over a unified diff: no AST, no base-vs-head structural comparison, no command execution, no policy contract, no receipt. `tamperguard` also covers lint/type-checker suppressions and loosened checker config across languages, which AICRG adopted for Python. This is the closest overlap with AICRG's test-integrity feature, and AICRG does not claim to be first to detect test tampering in diffs.
- AI PR reviewers (CodeRabbit, Copilot code review, Cursor Bugbot, Qodo/PR-Agent, Claude Code Action) produce natural-language comments. None of the consulted pages describe a deterministic, reproducible accept/reject decision tied to a policy and commit SHAs.
- Attestation standards (in-toto, Sigstore, SLSA, GitHub artifact attestations) describe how to sign and verify claims about artifacts and builds. They define the envelope, not the predicate "this patch met this review policy". A gate receipt can be expressed as an in-toto predicate later.
- Strongest gap: no consulted tool binds `{base SHA, head SHA, patch digest, policy digest, evidence, decision}` into one verifiable record, and none treats the patch's own edits to tests or CI as untrusted inputs to the gate.

## 2. Tool matrix

| Tool | Question it answers | Unit of analysis | Where it stops |
|---|---|---|---|
| GitHub code scanning / CodeQL | Does the code contain queryable vulnerability patterns? | Code state per commit; PR view compares head analysis to base analysis and shows new alerts `[search]` | Reports alerts. Does not judge whether a patch removed a test or assertion; a deleted test is just absent code (inference, no doc says otherwise). Requires a build/extraction per language. |
| Semgrep (CE/AppSec Platform) | Does the code match rules (patterns, taint in paid tier)? | Repo state; diff-aware mode scans head and baseline and reports only findings new since the baseline commit `[search]` | Needs rules written for each regression; no native notion of "protected paths" or "required evidence". Baseline env var does not work with unstaged changes or missing baseline hash `[search]`. |
| Ruff | Style, bug-prone patterns, 900+ rules including flake8-bandit (S) and flake8-pytest-style (PT) | File state (cached per file) | Rule violations in current files. Checks style of `pytest.raises`/asserts, not whether they got weaker relative to base. |
| mypy | Are statically typed parts type-consistent? | Module state | Only annotated code is covered; type errors do not alter runtime. |
| pyright | Same question as mypy, standards-based type checker | Module state | Same class of limits; README does not enumerate exclusions. |
| Bandit | Does the AST of this file match a known Python security-smell plugin? | File AST, current state | No diff awareness in its core description; README does not state limits. A pattern present before and after is indistinguishable from one introduced. |
| GitHub dependency-review-action | Does the PR add vulnerable or disallowed-licence dependencies? | Diff of dependency manifests in a PR | Needs GitHub dependency graph; private repos need Advanced Security; GitHub-hosted only; no source-code analysis. |
| pip-audit | Do installed or required packages have known vulnerabilities? | Environment or requirements file | Self-described as not a static analyzer, cannot detect malicious packages, transitive-vulnerability caveats. |
| OpenSSF Scorecard | How well does a project follow security practices? | Whole repository (about 24 checks, 0-10 each) | Not per-patch. |
| Socket (CLI/app) | Does a dependency show risky behaviour; what is new in this PR? | Package behaviour; diff scans against merge base report net-new findings `[README]` | Dependency-focused; commercial service backs the analysis. |
| reviewdog | Show linter output as PR comments on changed lines | Linter output filtered by diff (added, diff-context, file, nofilter) | Only reshapes other tools' output; `fail-level` defaults to `none`. |
| Danger JS / danger-python | Does the PR meet team conventions written as code (changelog, labels, file changes)? | PR metadata and changed-file list | Convention checks you write yourself; not evidence-bound, no built-in test-integrity or security semantics. |
| SonarQube / SonarCloud quality gate | Is the new code clean enough (issues, hotspots, coverage, duplication)? | New code period vs. overall | Measures new issues and coverage; coverage can be preserved while assertions are weakened (inference). Gate is configured server-side, not bound to commit-and-policy digest in a portable receipt `[unverified]`. |
| CodeRabbit, Copilot review, Bugbot, PR-Agent, Claude Code Action | LLM-generated review of a PR | PR diff plus context | Probabilistic comments. Not shown to produce reproducible decisions. |
| mutmut / cosmic-ray | Do tests detect injected faults in code? | Function-level mutants of source, with incremental re-test | Measures strength of the current test suite, not what changed in the tests. Slow. Does not read the diff of tests. |
| tampercheck / tamperguard | Did this diff weaken the checking? | Unified diff lines (regex; `tampercheck` uses `unidiff`) | Source read: line patterns only, no AST pairing of before/after assertions, no runs, no policy, no receipt. Multi-language and broader suppression coverage than AICRG. |
| SLSA / in-toto / Sigstore / GitHub attestations | Who built what, from what, and can it be verified? | Artifact and build | Do not define review-gate semantics; attestation only proves a claim was signed, not that it is true. |

## 3. What is already solved

- Vulnerability pattern detection in code: CodeQL, Semgrep, Bandit, Ruff-S. Mature, with SARIF outputs in common use.
- "Only new findings" scoping: CodeQL PR alerts, Semgrep baseline commit, reviewdog diff filter, Sonar new code, Socket diff scans. Diff-scoping of other tools' findings is a solved convention; AICRG should not reinvent it for those tools.
- Known-vulnerable dependency detection at PR time (dependency-review-action) and in an environment (pip-audit, backed by PyPA advisory DB and optionally OSV).
- Typing and lint gates (mypy, pyright, Ruff) as exit-code checks.
- Project-level hygiene scoring (Scorecard).
- Signing and verifying artifacts and attestation envelopes (Sigstore keyless signing with Fulcio and Rekor, in-toto statements, GitHub artifact attestations giving SLSA v1.0 Build L2, L3 with reusable workflows `[search]`).
- Incremental mutation testing for current-state test strength (mutmut).
- Convention-as-code on PR metadata (Danger).

## 4. What is poorly solved

1. Weakened tests are not gate failures in mainstream tools. Deleting a test, adding `skip`, broadening `pytest.raises(Exception)`, dropping an assertion, shrinking `parametrize` or editing a golden file leaves CodeQL, Semgrep, mypy and Bandit unaffected. Sonar's coverage condition may or may not move; line coverage can stay constant if the code is still executed. Only two small packages (`tampercheck`, `tamperguard`) were found that target this directly; both are line/regex based (source read, section 6a).
2. The oracle is editable by the patch. Research on coding agents describes tampering with tests, fixtures, snapshots, pytest.ini/tox.ini, CI config, timeouts and test selection `[search]`. A scanner running from the patch's own workflow files can be disabled by the patch. Mitigations in the benchmark world (restoring known test files) do not carry over to ordinary PRs. This is why AICRG reads its policy from the base commit, not head, and treats workflow and test-config edits in the patch as findings. Making the gate's own workflow immune to the patch needs platform support (required workflows / rulesets), see docs/GITHUB_ACTIONS.md.
3. AI reviewer output is unverifiable. Comments are natural language and vary between runs; a "no issues found" is not a reproducible claim. None of the consulted pages describe an evidence list or a policy under which the verdict was reached.
4. Results are not bound to exact inputs. CI check runs reference a SHA, but are not bound to patch digest and policy digest, and the policy is typically mutable, in the same repo, and changeable by the patch. Re-merging after a rebase can change the tested content while the check stays green (standard GitHub merge-queue or "require up-to-date branch" settings mitigate this, not evaluated here).
5. Quality gates measure issues and coverage, not evidence integrity. They answer "is the new code clean" rather than "were the checks that vouch for it intact".
6. No common representation of "required evidence". Which commands must have run, with which exit codes, on which tree, is encoded ad hoc in workflow YAML.
7. Dependency tools check vulnerabilities or behaviour; policy questions like "new runtime dependency without justification", direct URL deps, lockfile drift relative to the manifest, and typosquat-like names are only partially covered (Socket-style scanners cover behaviour and names commercially; `[unverified]` for lockfile-drift policy in any open tool).
8. Security-regression semantics ("auth check removed", `compare_digest` replaced, `verify=False` introduced, default flipped off) require comparing before and after at AST level. Semgrep baseline can detect newly introduced patterns that a rule describes; it cannot easily express "this call existed in base and no longer does" `[inference from docs; not tested]`.

## 5. Integrate, do not reimplement

| Tool | How aicrg consumes it |
|---|---|
| pytest | `required_checks` command; record exit code, duration, command string, tree SHA. Also parse junit XML (optional) to compare test counts base vs head. |
| Ruff | `required_checks` (`ruff check`, `ruff format --check`). Optionally `--output-format sarif` or JSON later. Do not reimplement S/PT rules. |
| mypy / pyright | `required_checks`. Policy may require "no new errors": run on base and head and compare counts (v2). |
| Bandit | `required_checks` with `-f json` or SARIF. Baseline comparison against base tree is an aicrg concern; Bandit itself supplies findings only. |
| pip-audit | `required_checks` (`pip-audit -r requirements.txt` or on lock output); JSON or CycloneDX output as evidence artifact. Network/availability failure maps to ERROR or REVIEW_REQUIRED per policy, never PASS. |
| Semgrep | `required_checks` with `--sarif` and `--baseline-commit <base SHA>`; aicrg supplies the base SHA from the contract. Ingest SARIF in a later release. |
| CodeQL | Do not run it. Accept an existing code-scanning result as optional evidence via SARIF import or GitHub API later, matched to head SHA. Treat absence as a policy setting. |
| dependency-review-action | Keep running it in CI. aicrg's own dependency delta is a cheap offline pre-check. Optionally record its conclusion as evidence by head SHA. |
| OpenSSF Scorecard | Out of scope per patch. Optionally a repo-level precondition (for example "Branch-Protection >= N") reported as informational. |
| Socket-style scanners | Optional external evidence via SARIF/JSON. Not required. |
| reviewdog | Not a dependency. aicrg can emit SARIF or rdjson-compatible findings so reviewdog or GitHub can annotate. `[reviewdog rdjson format not verified in this review]` |
| Danger | No integration needed. Different layer. |
| SonarQube/SonarCloud | Optional: read quality-gate status for the head SHA as evidence if the project uses it. `[API not verified here]` |
| mutmut / cosmic-ray | Optional, expensive `required_checks` command scoped to changed functions. Result is evidence, never run implicitly. |
| tampercheck / tamperguard | Can run as an additional `required_checks` command (both exit non-zero on findings) for languages AICRG does not parse. AICRG's AST analysis stays primary for Python because it pairs before/after assertions per test. |
| LLM reviewers | Optional hypothesis source only. Findings can add REVIEW_REQUIRED, never lower FAIL. |
| in-toto / Sigstore / GitHub attestations | Receipt v1 is plain JSON. Later: wrap as an in-toto Statement (subject: head commit and patch digest; custom predicate type), sign with cosign keyless or `actions/attest`, verify with `gh attestation verify` or cosign. Do not invent a signing scheme. |

## 6. What makes AICRG materially different

Draft thesis (from the brief): "Existing tools answer individual questions about a patch; AICRG asks whether the complete evidence package is sufficient to safely accept the patch."

Research suggests a sharper form, with the specific gap named:

> Existing tools evaluate code or a single property of a diff, and trust the patch's own tests, CI config and policy files. AICRG treats those as untrusted, evaluates what the patch changed about the evidence itself, and issues a decision bound to the exact commits, patch and policy under which it was reached.

Concretely, the differences that were not found in any consulted tool:
- The policy comes from a pinned source (base or an external file), digest-bound.
- Test-integrity and CI-integrity are first-class failure classes, with a fail-closed decision.
- Required evidence is declared (commands, exit codes, minimums) and missing evidence yields REVIEW_REQUIRED or ERROR, not silence.
- One versioned receipt ties decision, evidence and inputs; it is designed to be an attestation predicate.
- LLM output is structurally unable to approve.

Where AICRG is weaker than incumbents:
- Detection depth: CodeQL and Semgrep have far larger rule sets, dataflow or taint analysis and community maintenance. AICRG's security-regression checks are narrow AST patterns.
- Languages: Python-first; incumbents cover many languages.
- Test strength: mutation testing measures real fault detection; AICRG's test-integrity checks are structural heuristics and can miss semantic weakening or be evaded by rewrites (for example splitting an assertion into a helper that asserts less).
- Platform integration: GitHub-native tools get code-scanning UI, branch protection, merge queue and org-wide policy for free. A CLI-based receipt only matters if branch protection or the merge process actually requires and verifies it. Without that, an agent with write access to CI can skip the gate.
- Trust anchor: an unsigned receipt proves nothing against a hostile runner. Until it is signed and verified outside the patch's control, the claim is "reproducible", not "tamper-proof".
- Maturity: new, unreviewed, no adoption; `tampercheck`/`tamperguard` already cover part of the test-weakening feature (more languages, less structure).
- Heuristic false positives: legitimate test refactors will trigger REVIEW_REQUIRED; policy knobs and waivers are needed and are a design risk.

### 6a. Inspection of `tampercheck` and `tamperguard` (wheels read 2026-10-04)

| | tampercheck 0.1.1 | tamperguard 0.2.0 | AICRG |
|---|---|---|---|
| Input | unified diff (stdin, git range, `gh` PR) | unified diff | git base..head, resolved to SHAs |
| Method | ~29 regex rules over added/removed lines (`unidiff`) | ~21 regex rules, delta-aware counts | Python AST, per-test before/after pairing; YAML/TOML/INI parsing for CI and config |
| Languages | several (regex) | several (regex), incl. TS/Rust/Go suppressions | Python for code; language-agnostic for paths, workflows, manifests |
| Executes checks | no | no | yes, in a worktree of the exact head commit |
| Policy | CLI severity threshold | none found | typed, fail-closed review contract read from base |
| Output | findings + exit code (0/1/2) | score + exit code | versioned receipt bound to SHAs, patch digest, policy digest |
| Security regressions in source | swallowed errors | no | auth/TLS/shell/deserialization/compare_digest/defaults |

Neither tool's effectiveness was measured here. The comparison is about design scope only.

Open items to verify before publicising any novelty claim:
1. Run `tampercheck`/`tamperguard` over AICRG's corpora for a like-for-like detection comparison.
2. Check whether Semgrep or Sonar offer rules on test-file modification `[unverified]`.
3. Confirm CodeQL/Sonar behaviour on deleted tests empirically with a small repo.
4. Check GitHub rulesets / required workflows to see how far "the patch cannot change the gate" can be enforced natively.

## 7. Sources (all accessed 2026-10-04)

Fetched pages (content read):
- https://github.com/actions/dependency-review-action
- https://github.com/pypa/pip-audit
- https://github.com/ossf/scorecard
- https://github.com/reviewdog/reviewdog
- https://github.com/PyCQA/bandit (the `bandit` org path 404ed; content came from the redirect target)
- https://github.com/qodo-ai/pr-agent
- https://github.com/anthropics/claude-code-action
- https://github.com/boxed/mutmut
- https://github.com/astral-sh/ruff
- https://github.com/microsoft/pyright
- https://github.com/python/mypy
- https://github.com/in-toto/attestation
- https://github.com/sigstore/cosign
- https://github.com/SocketDev/socket-python-cli
- https://github.com/danger/danger-js

Search results used `[search]` (page text not fetched directly; excerpts only):
- https://semgrep.dev/docs/kb/semgrep-ci/trigger-diff-scans-env-var and https://docs.semgrep.dev/semgrep-ci/ci-environment-variables (Semgrep diff-aware and baseline)
- https://docs.sonarsource.com/sonarcloud/improving/clean-as-you-code and https://docs.sonarsource.com/sonarqube-server/10.8/instance-administration/analysis-functions/quality-gates/ (Clean as You Code, Sonar way conditions)
- https://docs.github.com/en/enterprise-cloud@latest/code-security/concepts/code-scanning (code scanning and PR comparison with base)
- https://docs.github.com/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds and https://github.blog/enterprise-software/devsecops/enhance-build-security-and-reach-slsa-level-3-with-github-artifact-attestations/ (artifact attestations, SLSA levels)
- https://arxiv.org/pdf/2606.26300 (The Verification Horizon), https://arxiv.org/pdf/2605.12673 (BenchJack); test-tampering and SWE-bench evaluation-trust statements come from search excerpts only
- https://pypi.org/project/tampercheck/ and https://pypi.org/project/tamperguard/0.1.0/ (descriptions from search excerpts; pages did not render)
- https://docs.coderabbit.ai/blog, https://www.morphllm.com/comparisons/coderabbit-vs-cursor-review, https://www.getpanto.ai/blog/bugbot-vs-coderabbit, https://aicodereview.cc/blog/coderabbit-vs-github-copilot (third-party and vendor descriptions of CodeRabbit, Bugbot, Copilot review; low confidence, no performance numbers reproduced here)

Not reached (blocked): docs.github.com direct, semgrep.dev direct, docs.sonarsource.com direct, bandit.readthedocs.io, danger.systems, slsa.dev, arxiv.org direct. Claims depending on these are marked `[search]` or `[unverified]`.
