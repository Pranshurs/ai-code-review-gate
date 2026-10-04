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


@dataclass(frozen=True, slots=True)
class RequiredCheck:
    name: str
    argv: tuple[str, ...]
    timeout_seconds: int = 900

    @property
    def command(self) -> str:
        return shlex.join(self.argv)


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
    env_passthrough: tuple[str, ...] = ()
    llm_reviewer: LLMReviewerPolicy | None = None

    def forbids(self, change_class: str) -> bool:
        if change_class not in FORBIDDEN_CHANGE_CLASSES:
            raise KeyError(change_class)  # programming error: unknown class
        return change_class in self.forbidden_changes

    def canonical(self) -> dict[str, Any]:
        data = asdict(self)
        data["forbidden_changes"] = sorted(self.forbidden_changes)
        data["required_checks"] = [
            {"name": c.name, "argv": list(c.argv), "timeout_seconds": c.timeout_seconds}
            for c in self.required_checks
        ]
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


def _checks(value: Any) -> tuple[RequiredCheck, ...]:
    if not isinstance(value, list):
        raise PolicyError("required_checks: expected a list")
    out: list[RequiredCheck] = []
    for i, item in enumerate(value):
        where = f"required_checks[{i}]"
        if isinstance(item, str):
            argv = _argv(where, item)
            out.append(RequiredCheck(name=item.strip(), argv=argv))
            continue
        if not isinstance(item, dict):
            raise PolicyError(f"{where}: expected a string or a mapping")
        _expect_keys(where, item, {"name", "command", "timeout_seconds"})
        if "name" not in item or "command" not in item:
            raise PolicyError(f"{where}: 'name' and 'command' are required")
        name = item["name"]
        if not isinstance(name, str) or not name.strip():
            raise PolicyError(f"{where}.name: expected a non-empty string")
        timeout = _int(f"{where}.timeout_seconds", item.get("timeout_seconds", 900), 1, 86400)
        out.append(RequiredCheck(name.strip(), _argv(f"{where}.command", item["command"]), timeout))
    names = [c.name for c in out]
    dupes = sorted({n for n in names if names.count(n) > 1})
    if dupes:
        raise PolicyError(f"required_checks: duplicate check names {dupes}")
    return tuple(out)


def _section(where: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PolicyError(f"{where}: expected a mapping")
    return value


def parse_contract(text: str) -> ReviewContract:
    try:
        data = yaml.load(text, Loader=_StrictLoader)  # noqa: S506 - strict SafeLoader subclass
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
        "execution",
        "llm_reviewer",
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
    if "execution" in data:
        sec = _section("execution", data["execution"])
        _expect_keys("execution", sec, {"env_passthrough"})
        if "env_passthrough" in sec:
            kwargs["env_passthrough"] = _str_list(
                "execution.env_passthrough", sec["env_passthrough"]
            )
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
