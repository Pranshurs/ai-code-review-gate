"""The Review Contract: a small, typed, fail-closed policy.

Design rules
------------
* Unknown keys, wrong types, duplicate keys and unknown enum values are errors.
  A malformed contract never degrades to "allow"; the gate reports ERROR.
* The contract can only make the gate *stricter* than its built-in floor for
  test-integrity and security signals: those findings are always at least
  REVIEW_REQUIRED; the contract decides which of them escalate to FAIL.
* Defaults are the strict choice.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from dataclasses import asdict, dataclass, field
from typing import Any

import yaml

from aicrg.globmatch import GlobError, compile_glob

SUPPORTED_VERSIONS = (1,)

# Change classes the contract can forbid (escalate to FAIL). Absent => all.
FORBIDDEN_CHANGE_CLASSES: dict[str, str] = {
    "test_deletion": "deleting test files or test functions",
    "security_check_disablement": (
        "removing auth/validation checks, disabling TLS verification, flipping security "
        "defaults off, removing constant-time comparison or security scanners"
    ),
    "secret_introduction": "adding credentials or private keys to the repository",
    "ci_test_bypass": "changing CI or test configuration so tests stop running or stop failing",
    "unsafe_execution": "shell execution with dynamic input, eval/exec, unsafe deserialization",
    "exception_swallowing": "broad exception handlers that silently swallow failures",
    "golden_data_modification": "editing golden/snapshot/expected-output data",
}

SURFACES = (
    "auth",
    "crypto",
    "migrations",
    "network",
    "filesystem",
    "subprocess",
    "ci",
    "dependencies",
    "build_release",
    "secrets_config",
    "tests",
    "input_validation",
    "concurrency",
    "deserialization",
    "gate_policy",
)

DEFAULT_GOLDEN_PATHS = (
    "**/golden/**",
    "**/goldens/**",
    "**/__snapshots__/**",
    "**/snapshots/**",
    "**/expected/**",
    "**/expected_output/**",
    "*.golden",
    "*.snap",
    "**/evals/**/expected*",
    "**/eval/**/expected*",
)

DEFAULT_POLICY_FILES = ("review-gate.yaml", "review-gate.yml", ".aicrg.yaml", ".aicrg.yml")


class PolicyError(ValueError):
    """The contract is malformed. Always maps to decision ERROR."""


EVIDENCE_SOURCES = ("head", "base", "bundle", "external")
REPORT_FORMATS = ("sarif", "junit", "cobertura", "lcov", "json")
PREEXISTING_FAILURE_MODES = ("fail", "review", "allow")
BLOCK_LEVELS = ("error", "warning", "note")


@dataclass(frozen=True, slots=True)
class RequiredCheck:
    """One piece of executed (or externally supplied) evidence.

    ``source`` says who controls the evidence content: ``head`` (the candidate),
    ``base``/``bundle`` (trusted evidence) or ``external`` (a report produced
    elsewhere and handed to the gate by the operator).
    """

    name: str
    argv: tuple[str, ...]
    timeout_seconds: int = 900
    source: str = "head"
    required: bool = True
    differential: bool = False
    preexisting_failure: str = "review"
    report_format: str | None = None
    report_path: str | None = None
    block_levels: tuple[str, ...] = ("error",)
    min_changed_coverage: float | None = None

    @property
    def command(self) -> str:
        return shlex.join(self.argv)

    def canonical(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "argv": list(self.argv),
            "timeout_seconds": self.timeout_seconds,
            "source": self.source,
            "required": self.required,
            "differential": self.differential,
            "preexisting_failure": self.preexisting_failure,
            "report_format": self.report_format,
            "report_path": self.report_path,
            "block_levels": list(self.block_levels),
            "min_changed_coverage": self.min_changed_coverage,
        }


@dataclass(frozen=True, slots=True)
class TrustedEvidence:
    name: str
    source: str  # "base" or "bundle"
    check: RequiredCheck
    paths: tuple[str, ...] = ()  # source: base
    bundle_path: str | None = None  # source: bundle (operator may override on the CLI)
    digest: str | None = None  # source: bundle
    mount: str | None = None  # source: bundle

    def canonical(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "source": self.source,
            "paths": list(self.paths),
            "bundle_path": self.bundle_path,
            "digest": self.digest,
            "mount": self.mount,
            "check": self.check.canonical(),
        }


@dataclass(frozen=True, slots=True)
class ContainerPolicy:
    image: str
    runtime: str = "docker"
    network: str = "none"
    cpus: float = 2.0
    memory_mb: int = 2048
    pids_limit: int = 512
    tmpfs_mb: int = 512
    user: str = "65534:65534"


@dataclass(frozen=True, slots=True)
class TestPotencyPolicy:
    command: tuple[str, ...]
    paths: tuple[str, ...] = ("**/*.py",)
    max_mutants: int = 40
    mutant_timeout_seconds: int = 120
    total_timeout_seconds: int = 1800
    on_survivor: str = "review"  # review | fail
    on_error: str = "review"  # review | error


@dataclass(frozen=True, slots=True)
class AttestationPolicy:
    required: bool = False
    method: str = "github"  # github | ssh
    repository: str | None = None  # github: owner/repo
    signer_workflow: str | None = None  # github: e.g. owner/repo/.github/workflows/gate.yml
    signer_ref: str = "refs/heads/main"  # github: the ref the signer workflow must run from
    allowed_signers: str | None = None  # ssh: repo-relative path at base
    identity: str | None = None  # ssh: principal expected in allowed_signers


@dataclass(frozen=True, slots=True)
class DependencyPolicy:
    allow_new_runtime_dependencies: bool = False
    allow_new_dev_dependencies: bool = True
    allowed_new_dependencies: tuple[str, ...] = ()
    max_new_dependencies: int = 3
    require_pinned_versions: bool = False
    allow_direct_url_dependencies: bool = False


@dataclass(frozen=True, slots=True)
class TestIntegrityPolicy:
    forbid_new_unconditional_skips: bool = True
    forbid_removed_security_assertions: bool = True
    forbid_assertion_weakening: bool = True


@dataclass(frozen=True, slots=True)
class LLMReviewerPolicy:
    command: tuple[str, ...] = ()
    timeout_seconds: int = 300
    required: bool = False  # if True, reviewer failure makes the gate ERROR
    env_passthrough: tuple[str, ...] = ()  # e.g. the provider API key; never given to checks


@dataclass(frozen=True, slots=True)
class ReviewContract:
    version: int = 1
    allowed_paths: tuple[str, ...] = ()
    protected_paths: tuple[str, ...] = ()
    required_checks: tuple[RequiredCheck, ...] = ()
    forbidden_changes: frozenset[str] = frozenset(FORBIDDEN_CHANGE_CLASSES)
    dependency_policy: DependencyPolicy = field(default_factory=DependencyPolicy)
    minimum_test_integrity: TestIntegrityPolicy = field(default_factory=TestIntegrityPolicy)
    review_required_surfaces: tuple[str, ...] = ()
    golden_paths: tuple[str, ...] = DEFAULT_GOLDEN_PATHS
    # Data that intentionally contains "bad" code (fixtures, corpora, vendored samples).
    # Still subject to allowed/protected path rules and risk classification; skipped by
    # content analysers. Workflows and the policy file itself are never excluded.
    exclude_from_analysis: tuple[str, ...] = ()
    env_passthrough: tuple[str, ...] = ()
    llm_reviewer: LLMReviewerPolicy | None = None
    executor: str = "local"  # local | container
    container: ContainerPolicy | None = None
    trusted_evidence: tuple[TrustedEvidence, ...] = ()
    external_evidence: tuple[RequiredCheck, ...] = ()
    test_potency: TestPotencyPolicy | None = None
    attestation: AttestationPolicy = field(default_factory=AttestationPolicy)

    def forbids(self, change_class: str) -> bool:
        if change_class not in FORBIDDEN_CHANGE_CLASSES:
            raise KeyError(change_class)  # programming error: unknown class
        return change_class in self.forbidden_changes

    def canonical(self) -> dict[str, Any]:
        data = asdict(self)
        data["forbidden_changes"] = sorted(self.forbidden_changes)
        data["required_checks"] = [c.canonical() for c in self.required_checks]
        data["trusted_evidence"] = [t.canonical() for t in self.trusted_evidence]
        data["external_evidence"] = [c.canonical() for c in self.external_evidence]
        return data

    def digest(self) -> str:
        blob = json.dumps(self.canonical(), sort_keys=True, separators=(",", ":"), default=list)
        return "sha256:" + hashlib.sha256(blob.encode()).hexdigest()


# --------------------------------------------------------------------------- parsing


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys."""


def _construct_mapping(loader: _StrictLoader, node: yaml.MappingNode, deep: bool = False) -> Any:
    seen: set[Any] = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise PolicyError(f"duplicate key {key!r} at line {key_node.start_mark.line + 1}")
        seen.add(key)
    return loader.construct_mapping(node, deep=deep)


_StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def _expect_keys(where: str, data: dict[str, Any], allowed: set[str]) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise PolicyError(f"{where}: unknown key(s) {unknown}; allowed: {sorted(allowed)}")


def _bool(where: str, value: Any) -> bool:
    if not isinstance(value, bool):
        raise PolicyError(f"{where}: expected true/false, got {type(value).__name__}")
    return value


def _int(where: str, value: Any, lo: int, hi: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not lo <= value <= hi:
        raise PolicyError(f"{where}: expected integer in [{lo}, {hi}], got {value!r}")
    return value


def _str_list(where: str, value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise PolicyError(f"{where}: expected a list of non-empty strings")
    return tuple(value)


def _globs(where: str, value: Any) -> tuple[str, ...]:
    pats = _str_list(where, value)
    for p in pats:
        try:
            compile_glob(p)
        except GlobError as exc:
            raise PolicyError(f"{where}: {exc}") from exc
    return pats


def _argv(where: str, command: Any) -> tuple[str, ...]:
    if isinstance(command, list):
        argv = _str_list(where, command)
    elif isinstance(command, str):
        try:
            argv = tuple(shlex.split(command))
        except ValueError as exc:
            raise PolicyError(f"{where}: cannot parse command: {exc}") from exc
    else:
        raise PolicyError(f"{where}: command must be a string or list of strings")
    if not argv:
        raise PolicyError(f"{where}: empty command")
    return argv


_CHECK_KEYS = {
    "name",
    "command",
    "timeout_seconds",
    "required",
    "differential",
    "preexisting_failure",
    "report",
    "block_levels",
    "min_changed_coverage",
}


def _rel_path(where: str, value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise PolicyError(f"{where}: expected a non-empty relative path")
    parts = value.replace("\\", "/").split("/")
    if value.startswith("/") or ".." in parts or parts[0] == ".git":
        raise PolicyError(f"{where}: path must be relative, without '..' or .git: {value!r}")
    return "/".join(p for p in parts if p not in ("", "."))


def _check(where: str, item: Any, source: str, *, need_command: bool = True) -> RequiredCheck:
    if isinstance(item, str) and need_command:
        return RequiredCheck(name=item.strip(), argv=_argv(where, item), source=source)
    if not isinstance(item, dict):
        raise PolicyError(f"{where}: expected a string or a mapping")
    _expect_keys(where, item, _CHECK_KEYS | ({"format"} if not need_command else set()))
    if "name" not in item:
        raise PolicyError(f"{where}: 'name' is required")
    if need_command and "command" not in item:
        raise PolicyError(f"{where}: 'command' is required")
    if not need_command and "command" in item:
        raise PolicyError(f"{where}: external evidence has no command (it is supplied)")
    name = item["name"]
    if not isinstance(name, str) or not name.strip():
        raise PolicyError(f"{where}.name: expected a non-empty string")
    kw: dict[str, Any] = {"name": name.strip(), "source": source}
    kw["argv"] = _argv(f"{where}.command", item["command"]) if need_command else ()
    kw["timeout_seconds"] = _int(
        f"{where}.timeout_seconds", item.get("timeout_seconds", 900), 1, 86400
    )
    kw["required"] = _bool(f"{where}.required", item.get("required", True))
    kw["differential"] = _bool(f"{where}.differential", item.get("differential", False))
    if not need_command and kw["differential"]:
        raise PolicyError(f"{where}: external evidence cannot be differential")
    mode = item.get("preexisting_failure", "review")
    if mode not in PREEXISTING_FAILURE_MODES:
        raise PolicyError(
            f"{where}.preexisting_failure: expected one of {list(PREEXISTING_FAILURE_MODES)}"
        )
    kw["preexisting_failure"] = mode
    if need_command and "report" in item:
        rep = _section(f"{where}.report", item["report"])
        _expect_keys(f"{where}.report", rep, {"format", "path"})
        if "format" not in rep or "path" not in rep:
            raise PolicyError(f"{where}.report: 'format' and 'path' are required")
        kw["report_format"] = rep["format"]
        kw["report_path"] = _rel_path(f"{where}.report.path", rep["path"])
    elif not need_command:
        if "report" in item:
            raise PolicyError(f"{where}: external evidence takes 'format', not 'report'")
        if "format" not in item:
            raise PolicyError(f"{where}: 'format' is required")
        kw["report_format"] = item["format"]
    if kw.get("report_format") is not None and kw["report_format"] not in REPORT_FORMATS:
        raise PolicyError(f"{where}: report format must be one of {list(REPORT_FORMATS)}")
    if "block_levels" in item:
        levels = _str_list(f"{where}.block_levels", item["block_levels"])
        bad = sorted(set(levels) - set(BLOCK_LEVELS))
        if bad:
            raise PolicyError(f"{where}.block_levels: unknown level(s) {bad}")
        kw["block_levels"] = levels
    if "min_changed_coverage" in item:
        v = item["min_changed_coverage"]
        if isinstance(v, bool) or not isinstance(v, int | float) or not 0 <= v <= 1:
            raise PolicyError(f"{where}.min_changed_coverage: expected a number in [0, 1]")
        if kw.get("report_format") not in ("cobertura", "lcov"):
            raise PolicyError(f"{where}.min_changed_coverage needs a cobertura or lcov report")
        kw["min_changed_coverage"] = float(v)
    return RequiredCheck(**kw)


def _unique(where: str, names: list[str]) -> None:
    dupes = sorted({n for n in names if names.count(n) > 1})
    if dupes:
        raise PolicyError(f"{where}: duplicate evidence names {dupes}")


def _checks(value: Any) -> tuple[RequiredCheck, ...]:
    if not isinstance(value, list):
        raise PolicyError("required_checks: expected a list")
    out = [_check(f"required_checks[{i}]", item, "head") for i, item in enumerate(value)]
    _unique("required_checks", [c.name for c in out])
    return tuple(out)


_DIGEST_RE_TEXT = r"^sha256:[0-9a-f]{64}$"


def _trusted(value: Any) -> tuple[TrustedEvidence, ...]:
    if not isinstance(value, list) or not value:
        raise PolicyError("trusted_evidence: expected a non-empty list")
    out: list[TrustedEvidence] = []
    for i, item in enumerate(value):
        where = f"trusted_evidence[{i}]"
        sec = _section(where, item)
        source = sec.get("source")
        if source not in ("base", "bundle"):
            raise PolicyError(f"{where}.source: expected 'base' or 'bundle'")
        extra = {"source", "paths"} if source == "base" else {"source", "bundle", "digest", "mount"}
        _expect_keys(where, sec, _CHECK_KEYS | extra)
        check_item = {k: v for k, v in sec.items() if k in _CHECK_KEYS}
        check = _check(where, check_item, source)
        if source == "base":
            if "paths" not in sec:
                raise PolicyError(f"{where}: source 'base' needs 'paths'")
            paths = _globs(f"{where}.paths", sec["paths"])
            if not paths:
                raise PolicyError(f"{where}.paths: must not be empty")
            out.append(TrustedEvidence(check.name, "base", check, paths=paths))
        else:
            for k in ("digest", "mount"):
                if k not in sec:
                    raise PolicyError(f"{where}: source 'bundle' needs '{k}'")
            digest = sec["digest"]
            if not isinstance(digest, str) or not re.match(_DIGEST_RE_TEXT, digest):
                raise PolicyError(f"{where}.digest: expected 'sha256:<64 hex>'")
            bundle = sec.get("bundle")
            if bundle is not None and (not isinstance(bundle, str) or not bundle):
                raise PolicyError(f"{where}.bundle: expected a path")
            out.append(
                TrustedEvidence(
                    check.name,
                    "bundle",
                    check,
                    bundle_path=bundle,
                    digest=digest,
                    mount=_rel_path(f"{where}.mount", sec["mount"]),
                )
            )
    _unique("trusted_evidence", [t.name for t in out])
    return tuple(out)


def _external(value: Any) -> tuple[RequiredCheck, ...]:
    if not isinstance(value, list) or not value:
        raise PolicyError("external_evidence: expected a non-empty list")
    out = [
        _check(f"external_evidence[{i}]", item, "external", need_command=False)
        for i, item in enumerate(value)
    ]
    _unique("external_evidence", [c.name for c in out])
    return tuple(out)


def _execution(sec: dict[str, Any], kwargs: dict[str, Any]) -> None:
    _expect_keys("execution", sec, {"env_passthrough", "executor", "container"})
    if "env_passthrough" in sec:
        kwargs["env_passthrough"] = _str_list("execution.env_passthrough", sec["env_passthrough"])
    executor = sec.get("executor", "local")
    if executor not in ("local", "container"):
        raise PolicyError("execution.executor: expected 'local' or 'container'")
    kwargs["executor"] = executor
    if "container" in sec:
        c = _section("execution.container", sec["container"])
        _expect_keys("execution.container", c, set(ContainerPolicy.__dataclass_fields__))
        if "image" not in c or not isinstance(c["image"], str) or not c["image"]:
            raise PolicyError("execution.container.image: required")
        ck: dict[str, Any] = {"image": c["image"]}
        if "runtime" in c:
            if c["runtime"] not in ("docker", "podman"):
                raise PolicyError("execution.container.runtime: expected docker or podman")
            ck["runtime"] = c["runtime"]
        if "network" in c:
            if c["network"] not in ("none", "enabled"):
                raise PolicyError("execution.container.network: expected 'none' or 'enabled'")
            ck["network"] = c["network"]
        if "cpus" in c:
            v = c["cpus"]
            if isinstance(v, bool) or not isinstance(v, int | float) or not 0 < v <= 256:
                raise PolicyError("execution.container.cpus: expected a number in (0, 256]")
            ck["cpus"] = float(v)
        for k, lo, hi in (
            ("memory_mb", 64, 1_048_576),
            ("pids_limit", 16, 65536),
            ("tmpfs_mb", 1, 65536),
        ):
            if k in c:
                ck[k] = _int(f"execution.container.{k}", c[k], lo, hi)
        if "user" in c:
            u = c["user"]
            if not isinstance(u, str) or not u.replace(":", "").isdigit() or u.split(":")[0] == "0":
                raise PolicyError("execution.container.user: numeric non-root uid[:gid] required")
            ck["user"] = u
        kwargs["container"] = ContainerPolicy(**ck)
    if executor == "container" and "container" not in kwargs:
        raise PolicyError("execution.executor 'container' needs an execution.container section")


def _potency(sec: dict[str, Any]) -> TestPotencyPolicy:
    _expect_keys("test_potency", sec, set(TestPotencyPolicy.__dataclass_fields__))
    if "command" not in sec:
        raise PolicyError("test_potency: 'command' is required")
    kw: dict[str, Any] = {"command": _argv("test_potency.command", sec["command"])}
    if "paths" in sec:
        kw["paths"] = _globs("test_potency.paths", sec["paths"])
    for k, lo, hi in (
        ("max_mutants", 1, 10_000),
        ("mutant_timeout_seconds", 1, 86400),
        ("total_timeout_seconds", 1, 86400),
    ):
        if k in sec:
            kw[k] = _int(f"test_potency.{k}", sec[k], lo, hi)
    if sec.get("on_survivor", "review") not in ("review", "fail"):
        raise PolicyError("test_potency.on_survivor: expected 'review' or 'fail'")
    if sec.get("on_error", "review") not in ("review", "error"):
        raise PolicyError("test_potency.on_error: expected 'review' or 'error'")
    kw["on_survivor"] = sec.get("on_survivor", "review")
    kw["on_error"] = sec.get("on_error", "review")
    return TestPotencyPolicy(**kw)


def _attestation(sec: dict[str, Any]) -> AttestationPolicy:
    _expect_keys("attestation", sec, set(AttestationPolicy.__dataclass_fields__))
    kw: dict[str, Any] = {"required": _bool("attestation.required", sec.get("required", False))}
    method = sec.get("method", "github")
    if method not in ("github", "ssh"):
        raise PolicyError("attestation.method: expected 'github' or 'ssh'")
    kw["method"] = method
    for k in ("repository", "signer_workflow", "signer_ref", "allowed_signers", "identity"):
        if k in sec:
            v = sec[k]
            if not isinstance(v, str) or not v:
                raise PolicyError(f"attestation.{k}: expected a non-empty string")
            kw[k] = v
    if method == "ssh" and kw["required"]:
        if "allowed_signers" not in kw or "identity" not in kw:
            raise PolicyError("attestation (ssh): 'allowed_signers' and 'identity' are required")
        kw["allowed_signers"] = _rel_path("attestation.allowed_signers", kw["allowed_signers"])
    if method == "github" and kw["required"] and not {"repository", "signer_workflow"} <= set(kw):
        # Unpinned, an attestation made by a PR-edited workflow would verify.
        raise PolicyError("attestation (github): 'repository' and 'signer_workflow' are required")
    return AttestationPolicy(**kw)


def _section(where: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PolicyError(f"{where}: expected a mapping")
    return value


def parse_contract(text: str) -> ReviewContract:
    try:
        loader = _StrictLoader(text)  # SafeLoader subclass; same steps as yaml.safe_load
        try:
            data = loader.get_single_data()
        finally:
            loader.dispose()
    except PolicyError:
        raise
    except yaml.YAMLError as exc:
        raise PolicyError(f"policy is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError("policy must be a YAML mapping")
    return contract_from_mapping(data)


def contract_from_mapping(data: dict[str, Any]) -> ReviewContract:
    top = {
        "version",
        "allowed_paths",
        "protected_paths",
        "required_checks",
        "forbidden_changes",
        "dependency_policy",
        "minimum_test_integrity",
        "review_required_surfaces",
        "golden_paths",
        "exclude_from_analysis",
        "execution",
        "llm_reviewer",
        "trusted_evidence",
        "external_evidence",
        "test_potency",
        "attestation",
    }
    _expect_keys("policy", data, top)
    if "version" not in data:
        raise PolicyError("policy: 'version' is required")
    version = data["version"]
    if isinstance(version, bool) or version not in SUPPORTED_VERSIONS:
        raise PolicyError(
            f"policy: unsupported version {version!r}; supported {SUPPORTED_VERSIONS}"
        )

    kwargs: dict[str, Any] = {"version": version}
    if "allowed_paths" in data:
        kwargs["allowed_paths"] = _globs("allowed_paths", data["allowed_paths"])
        if not kwargs["allowed_paths"]:
            raise PolicyError("allowed_paths: empty list would forbid every change; omit the key")
    if "protected_paths" in data:
        kwargs["protected_paths"] = _globs("protected_paths", data["protected_paths"])
    if "required_checks" in data:
        kwargs["required_checks"] = _checks(data["required_checks"])
    if "forbidden_changes" in data:
        classes = _str_list("forbidden_changes", data["forbidden_changes"])
        unknown = sorted(set(classes) - set(FORBIDDEN_CHANGE_CLASSES))
        if unknown:
            raise PolicyError(
                f"forbidden_changes: unknown class(es) {unknown}; "
                f"known: {sorted(FORBIDDEN_CHANGE_CLASSES)}"
            )
        kwargs["forbidden_changes"] = frozenset(classes)
    if "dependency_policy" in data:
        sec = _section("dependency_policy", data["dependency_policy"])
        _expect_keys("dependency_policy", sec, set(DependencyPolicy.__dataclass_fields__))
        dp: dict[str, Any] = {}
        for key, val in sec.items():
            where = f"dependency_policy.{key}"
            if key == "allowed_new_dependencies":
                dp[key] = tuple(s.lower() for s in _str_list(where, val))
            elif key == "max_new_dependencies":
                dp[key] = _int(where, val, 0, 10_000)
            else:
                dp[key] = _bool(where, val)
        kwargs["dependency_policy"] = DependencyPolicy(**dp)
    if "minimum_test_integrity" in data:
        sec = _section("minimum_test_integrity", data["minimum_test_integrity"])
        _expect_keys("minimum_test_integrity", sec, set(TestIntegrityPolicy.__dataclass_fields__))
        kwargs["minimum_test_integrity"] = TestIntegrityPolicy(
            **{k: _bool(f"minimum_test_integrity.{k}", v) for k, v in sec.items()}
        )
    if "review_required_surfaces" in data:
        surfaces = _str_list("review_required_surfaces", data["review_required_surfaces"])
        unknown = sorted(set(surfaces) - set(SURFACES))
        if unknown:
            raise PolicyError(f"review_required_surfaces: unknown surface(s) {unknown}")
        kwargs["review_required_surfaces"] = surfaces
    if "golden_paths" in data:
        kwargs["golden_paths"] = DEFAULT_GOLDEN_PATHS + _globs("golden_paths", data["golden_paths"])
    if "exclude_from_analysis" in data:
        kwargs["exclude_from_analysis"] = _globs(
            "exclude_from_analysis", data["exclude_from_analysis"]
        )
    if "execution" in data:
        _execution(_section("execution", data["execution"]), kwargs)
    if "trusted_evidence" in data:
        kwargs["trusted_evidence"] = _trusted(data["trusted_evidence"])
    if "external_evidence" in data:
        kwargs["external_evidence"] = _external(data["external_evidence"])
    if "test_potency" in data:
        kwargs["test_potency"] = _potency(_section("test_potency", data["test_potency"]))
    if "attestation" in data:
        kwargs["attestation"] = _attestation(_section("attestation", data["attestation"]))
    names = [c.name for c in kwargs.get("required_checks", ())]
    names += [t.name for t in kwargs.get("trusted_evidence", ())]
    names += [c.name for c in kwargs.get("external_evidence", ())]
    _unique("evidence", names)
    if "llm_reviewer" in data:
        sec = _section("llm_reviewer", data["llm_reviewer"])
        _expect_keys(
            "llm_reviewer", sec, {"command", "timeout_seconds", "required", "env_passthrough"}
        )
        if "command" not in sec:
            raise PolicyError("llm_reviewer: 'command' is required")
        kwargs["llm_reviewer"] = LLMReviewerPolicy(
            command=_argv("llm_reviewer.command", sec["command"]),
            timeout_seconds=_int(
                "llm_reviewer.timeout_seconds", sec.get("timeout_seconds", 300), 1, 3600
            ),
            required=_bool("llm_reviewer.required", sec.get("required", False)),
            env_passthrough=_str_list(
                "llm_reviewer.env_passthrough", sec.get("env_passthrough", [])
            ),
        )
    return ReviewContract(**kwargs)
