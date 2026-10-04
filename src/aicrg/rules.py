"""Registry of every finding the gate can emit.

Each rule states its category, how it is detected (deterministic vs heuristic)
and how severity is chosen:

* ``change_class``: if the contract forbids that class the finding BLOCKs,
  otherwise it requires REVIEW. Never silently passes.
* ``fixed``: severity does not depend on the contract.
* ``caller``: the analyser computes severity from a specific contract field and
  documents the rule here.
"""

from __future__ import annotations

from dataclasses import dataclass

from aicrg.model import Finding, Kind, Severity
from aicrg.policy.contract import ReviewContract

B, R, A = Severity.BLOCK, Severity.REVIEW, Severity.ADVISORY
DET, HEU = Kind.DETERMINISTIC, Kind.HEURISTIC


@dataclass(frozen=True, slots=True)
class Rule:
    code: str
    category: str
    kind: Kind
    summary: str
    change_class: str | None = None
    fixed: Severity | None = None  # None with change_class None => caller decides


_RULES: tuple[Rule, ...] = (
    # ---- contract ----------------------------------------------------------------
    Rule("path_outside_contract", "contract", DET, "changed file outside allowed_paths", fixed=B),
    Rule(
        "protected_path_modified", "contract", DET, "changed file matches protected_paths", fixed=B
    ),
    Rule(
        "policy_modified",
        "contract",
        DET,
        "patch edits the review contract it is judged by (base policy still applies)",
        fixed=R,
    ),
    Rule(
        "review_required_surface",
        "contract",
        DET,
        "patch touches a surface the contract always routes to human review",
        fixed=R,
    ),
    Rule(
        "insufficient_evidence",
        "evidence",
        DET,
        "high-risk patch with no executed required checks",
        fixed=R,
    ),
    Rule("required_check_failed", "evidence", DET, "a required check command failed", fixed=B),
    # ---- test integrity ----------------------------------------------------------
    Rule(
        "test_file_deleted",
        "test_integrity",
        DET,
        "test file deleted",
        change_class="test_deletion",
    ),
    Rule(
        "test_function_removed",
        "test_integrity",
        DET,
        "test function removed",
        change_class="test_deletion",
    ),
    Rule(
        "test_function_renamed",
        "test_integrity",
        HEU,
        "test function renamed with identical assertions",
        fixed=A,
    ),
    Rule(
        "assertion_removed",
        "test_integrity",
        DET,
        "assertions removed from a test (BLOCK for security tests when "
        "forbid_removed_security_assertions)",
    ),
    Rule(
        "assertion_weakened",
        "test_integrity",
        HEU,
        "assertion replaced by a weaker one on the same subject (forbid_assertion_weakening)",
    ),
    Rule(
        "expected_exception_broadened",
        "test_integrity",
        DET,
        "pytest.raises/assertRaises widened to a broader exception or lost match= "
        "(forbid_assertion_weakening)",
    ),
    Rule(
        "vacuous_assertion_added",
        "test_integrity",
        DET,
        "assertion that cannot fail added (forbid_assertion_weakening)",
    ),
    Rule(
        "unreachable_assertions",
        "test_integrity",
        DET,
        "test returns before its assertions (forbid_assertion_weakening)",
    ),
    Rule(
        "assertion_swallowed",
        "test_integrity",
        DET,
        "assertions wrapped in an exception handler that hides failure "
        "(forbid_assertion_weakening)",
    ),
    Rule(
        "assertion_subject_dropped",
        "test_integrity",
        HEU,
        "an asserted-on value is no longer asserted on (replaced by an unrelated assertion)",
        fixed=R,
    ),
    Rule(
        "golden_regenerated_by_test",
        "test_integrity",
        DET,
        "test code writes to the golden/expected data it compares against",
        change_class="golden_data_modification",
    ),
    Rule(
        "expected_value_changed",
        "test_integrity",
        HEU,
        "expected literal in an assertion changed",
        fixed=R,
    ),
    Rule(
        "unconditional_skip_added",
        "test_integrity",
        DET,
        "unconditional skip added (forbid_new_unconditional_skips)",
    ),
    Rule("xfail_added", "test_integrity", DET, "xfail marker added", fixed=R),
    Rule("conditional_skip_added", "test_integrity", DET, "conditional skip added", fixed=A),
    Rule(
        "parametrize_cases_reduced",
        "test_integrity",
        DET,
        "parametrized cases removed (BLOCK for security tests when "
        "forbid_removed_security_assertions)",
    ),
    Rule(
        "golden_data_modified",
        "test_integrity",
        DET,
        "golden/snapshot/expected data edited",
        change_class="golden_data_modification",
    ),
    Rule(
        "collection_hook_modified",
        "test_integrity",
        HEU,
        "conftest collection/skip hooks changed",
        fixed=R,
    ),
    Rule(
        "test_config_excludes_tests",
        "test_integrity",
        DET,
        "pytest configuration now ignores or deselects tests",
        change_class="ci_test_bypass",
    ),
    Rule(
        "coverage_threshold_lowered",
        "test_integrity",
        DET,
        "coverage fail_under lowered",
        change_class="ci_test_bypass",
    ),
    Rule(
        "checker_suppression_added",
        "test_integrity",
        DET,
        "file-wide lint/type-check suppression added",
        change_class="ci_test_bypass",
    ),
    Rule(
        "checker_config_loosened",
        "test_integrity",
        DET,
        "ruff/mypy configuration made less strict",
        change_class="ci_test_bypass",
    ),
    Rule(
        "inline_suppression_added",
        "test_integrity",
        DET,
        "inline noqa/type: ignore/pragma: no cover added",
        fixed=A,
    ),
    Rule(
        "security_suppression_added",
        "security",
        DET,
        "security scanner suppression (# nosec / nosemgrep) added",
        fixed=R,
    ),
    Rule(
        "config_unparseable",
        "test_integrity",
        DET,
        "test/checker configuration could not be parsed; analysis incomplete",
        fixed=R,
    ),
    Rule(
        "unparseable_python",
        "analysis",
        DET,
        "changed Python file could not be parsed; analysis incomplete",
        fixed=R,
    ),
    # ---- CI ----------------------------------------------------------------------
    Rule(
        "ci_test_step_removed",
        "ci_integrity",
        DET,
        "workflow no longer runs a test command",
        change_class="ci_test_bypass",
    ),
    Rule(
        "ci_failure_masked",
        "ci_integrity",
        DET,
        "workflow masks failures (continue-on-error, || true, exit 0)",
        change_class="ci_test_bypass",
    ),
    Rule(
        "ci_job_disabled",
        "ci_integrity",
        DET,
        "workflow job/step disabled with a constant if",
        change_class="ci_test_bypass",
    ),
    Rule(
        "ci_tests_deselected",
        "ci_integrity",
        DET,
        "test command now ignores/deselects tests",
        change_class="ci_test_bypass",
    ),
    Rule(
        "ci_trigger_removed",
        "ci_integrity",
        DET,
        "workflow no longer runs on pull requests/pushes",
        change_class="ci_test_bypass",
    ),
    Rule("ci_paths_ignore_added", "ci_integrity", DET, "workflow paths filter added", fixed=R),
    Rule(
        "security_scanner_removed",
        "ci_integrity",
        DET,
        "security scanning step removed",
        change_class="security_check_disablement",
    ),
    Rule(
        "dangerous_trigger_added",
        "ci_integrity",
        DET,
        "pull_request_target/workflow_run trigger added",
        change_class="security_check_disablement",
    ),
    Rule(
        "workflow_permissions_widened",
        "ci_integrity",
        DET,
        "workflow token permissions widened",
        fixed=R,
    ),
    Rule(
        "unpinned_action_added",
        "ci_integrity",
        DET,
        "third-party action referenced by mutable tag",
        fixed=A,
    ),
    Rule(
        "ci_config_unparseable", "ci_integrity", DET, "workflow YAML could not be parsed", fixed=R
    ),
    # ---- security ----------------------------------------------------------------
    Rule(
        "auth_check_removed",
        "security",
        HEU,
        "authorization/denial check removed from function",
        change_class="security_check_disablement",
    ),
    Rule(
        "auth_decorator_removed",
        "security",
        DET,
        "auth decorator removed from function",
        change_class="security_check_disablement",
    ),
    Rule("input_validation_removed", "security", HEU, "validation call or raise removed", fixed=R),
    Rule(
        "tls_verification_disabled",
        "security",
        DET,
        "TLS certificate/hostname verification off",
        change_class="security_check_disablement",
    ),
    Rule(
        "security_default_disabled",
        "security",
        HEU,
        "security-named flag/default changed from True to False",
        change_class="security_check_disablement",
    ),
    Rule(
        "constant_time_compare_removed",
        "security",
        DET,
        "constant-time comparison removed",
        change_class="security_check_disablement",
    ),
    Rule("path_restriction_weakened", "security", HEU, "path containment check removed", fixed=R),
    Rule(
        "fail_open_handler",
        "security",
        HEU,
        "exception handler now grants/returns success",
        change_class="security_check_disablement",
    ),
    Rule(
        "shell_injection_risk",
        "security",
        DET,
        "shell execution with a dynamically built command",
        change_class="unsafe_execution",
    ),
    Rule(
        "shell_execution_added", "security", DET, "shell execution with a literal command", fixed=R
    ),
    Rule(
        "unsafe_deserialization",
        "security",
        DET,
        "unsafe deserialization call added",
        change_class="unsafe_execution",
    ),
    Rule(
        "dynamic_code_execution",
        "security",
        DET,
        "eval/exec added",
        change_class="unsafe_execution",
    ),
    Rule(
        "broad_exception_swallowed",
        "security",
        DET,
        "broad except handler that discards the error",
        change_class="exception_swallowing",
    ),
    Rule("weak_hash_added", "security", DET, "md5/sha1 use added", fixed=A),
    Rule("debug_mode_enabled", "security", DET, "debug mode switched on", fixed=R),
    Rule(
        "secret_introduced",
        "security",
        DET,
        "credential or private key added",
        change_class="secret_introduction",
    ),
    # ---- dependencies ------------------------------------------------------------
    Rule(
        "new_runtime_dependency",
        "dependencies",
        DET,
        "new runtime dependency (allow_new_runtime_dependencies / allowed_new_dependencies)",
    ),
    Rule(
        "new_dev_dependency",
        "dependencies",
        DET,
        "new development dependency (allow_new_dev_dependencies)",
    ),
    Rule(
        "direct_url_dependency",
        "dependencies",
        DET,
        "dependency from URL/VCS/path (allow_direct_url_dependencies)",
    ),
    Rule(
        "unpinned_dependency",
        "dependencies",
        DET,
        "dependency without exact pin (require_pinned_versions)",
    ),
    Rule(
        "dependency_expansion",
        "dependencies",
        DET,
        "more new dependencies than max_new_dependencies",
        fixed=B,
    ),
    Rule(
        "suspicious_package_name",
        "dependencies",
        HEU,
        "new dependency name is one edit away from a popular package",
        fixed=R,
    ),
    Rule(
        "package_index_changed",
        "dependencies",
        DET,
        "package index/source configuration changed",
        fixed=R,
    ),
    Rule(
        "lockfile_not_updated",
        "dependencies",
        DET,
        "manifest dependencies changed but lockfile did not",
        fixed=R,
    ),
    Rule("dependency_removed", "dependencies", DET, "dependency removed", fixed=A),
    Rule(
        "dependency_manifest_unparseable",
        "dependencies",
        DET,
        "dependency manifest could not be parsed",
        fixed=R,
    ),
    # ---- reviewer model ----------------------------------------------------------
    Rule(
        "llm_hypothesis",
        "llm_review",
        Kind.HYPOTHESIS,
        "reviewer-model hypothesis (never proof; at most REVIEW)",
    ),
)

RULES: dict[str, Rule] = {r.code: r for r in _RULES}


def finding(
    code: str,
    contract: ReviewContract,
    message: str,
    *,
    file: str | None = None,
    line: int | None = None,
    before: str | None = None,
    after: str | None = None,
    severity: Severity | None = None,
    provider: str = "aicrg",
) -> Finding:
    rule = RULES[code]
    if rule.fixed is not None:
        sev = rule.fixed
        if severity is not None and severity != sev:
            raise ValueError(f"{code}: severity is fixed at {sev}")
    elif rule.change_class is not None:
        sev = B if contract.forbids(rule.change_class) else R
        if severity is not None:
            raise ValueError(f"{code}: severity comes from change class {rule.change_class}")
    else:
        if severity is None:
            raise ValueError(f"{code}: caller must choose severity")
        sev = severity
    return Finding(
        code=code,
        category=rule.category,
        severity=sev,
        kind=rule.kind,
        message=message,
        file=file,
        line=line,
        before=_clip(before),
        after=_clip(after),
        provider=provider,
    )


def _clip(text: str | None, limit: int = 300) -> str | None:
    if text is None:
        return None
    text = text.strip()
    return text if len(text) <= limit else text[: limit - 3] + "..."
