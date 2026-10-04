"""Risk-surface classification.

Two deterministic signals, both explainable in the receipt:

1. **Path rules**: the file's location says what it is (workflows, manifests,
   migrations, tests...).
2. **Python AST of the changed region**: imports and calls inside the
   functions/statements the patch actually touched (on both sides) say what the
   code does (subprocess, crypto, network, filesystem...).

This is a heuristic. It over-approximates on purpose: misclassifying a benign
file as sensitive costs a stricter evidence bar; the reverse costs a missed
review. The receipt records *why* each surface was assigned.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from enum import IntEnum

from aicrg.analysis.context import PatchContext, is_test_path
from aicrg.analysis.pyast import call_name, dotted, iter_functions, touches
from aicrg.git.diff import FileChange
from aicrg.globmatch import match_any


class RiskLevel(IntEnum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3


SURFACE_RISK: dict[str, RiskLevel] = {
    "auth": RiskLevel.CRITICAL,
    "crypto": RiskLevel.CRITICAL,
    "ci": RiskLevel.CRITICAL,
    "secrets_config": RiskLevel.CRITICAL,
    "gate_policy": RiskLevel.CRITICAL,
    "migrations": RiskLevel.HIGH,
    "subprocess": RiskLevel.HIGH,
    "deserialization": RiskLevel.HIGH,
    "dependencies": RiskLevel.HIGH,
    "build_release": RiskLevel.HIGH,
    "input_validation": RiskLevel.HIGH,
    "network": RiskLevel.MEDIUM,
    "filesystem": RiskLevel.MEDIUM,
    "concurrency": RiskLevel.MEDIUM,
    "tests": RiskLevel.MEDIUM,
}

PATH_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "ci",
        (
            ".github/workflows/**",
            ".github/actions/**",
            ".gitlab-ci.yml",
            ".circleci/**",
            "azure-pipelines.yml",
            "Jenkinsfile",
            ".pre-commit-config.yaml",
            "noxfile.py",
            "tox.ini",
            "Makefile",
        ),
    ),
    (
        "dependencies",
        (
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
            "requirements*.txt",
            "requirements/**",
            "*.lock",
            "Pipfile",
            "package.json",
            "package-lock.json",
            "pnpm-lock.yaml",
            "go.mod",
            "go.sum",
            "Cargo.toml",
            "constraints*.txt",
        ),
    ),
    (
        "build_release",
        (
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
            "MANIFEST.in",
            "Dockerfile",
            "**/Dockerfile",
            "*.spec",
            ".github/release*",
            ".goreleaser.yml",
            "build.py",
        ),
    ),
    ("migrations", ("**/migrations/**", "**/alembic/**", "**/migrate/**", "*.sql")),
    (
        "auth",
        (
            "**/auth/**",
            "**/auth*.py",
            "**/*permission*",
            "**/*rbac*",
            "**/*acl*",
            "**/login*",
            "**/session*.py",
            "**/oauth*",
            "**/jwt*",
            "**/policy*.py",
        ),
    ),
    ("crypto", ("**/crypto/**", "**/*crypto*", "**/*cipher*", "**/*signing*", "**/*hmac*")),
    (
        "secrets_config",
        (
            ".env",
            ".env.*",
            "**/*secret*",
            "**/*credential*",
            "*.pem",
            "*.key",
            "**/settings.py",
            "**/config/**",
            "**/*.cfg",
            ".gitignore",
            ".gitattributes",
            "CODEOWNERS",
            ".github/CODEOWNERS",
        ),
    ),
    ("network", ("**/client*.py", "**/http*.py", "**/api/**")),
    ("input_validation", ("**/*valid*", "**/*sanitiz*", "**/schemas/**", "**/forms*.py")),
    ("concurrency", ("**/*retry*", "**/*idempoten*", "**/*lock*.py", "**/*queue*", "**/*worker*")),
)

# (surface, imported module prefixes, called-name regex)
AST_RULES: tuple[tuple[str, tuple[str, ...], re.Pattern[str] | None], ...] = (
    (
        "subprocess",
        ("subprocess", "pexpect", "sh", "plumbum"),
        re.compile(
            r"^(os\.(system|popen|exec\w*|spawn\w*)|subprocess\.\w+|asyncio\.create_subprocess_\w+)$"
        ),
    ),
    (
        "crypto",
        (
            "hashlib",
            "hmac",
            "secrets",
            "cryptography",
            "Crypto",
            "nacl",
            "jwt",
            "jose",
            "bcrypt",
            "passlib",
            "argon2",
            "ssl",
        ),
        re.compile(
            r"(compare_digest|hashpw|checkpw|encrypt|decrypt|sign|verify_signature|token_hex)$"
        ),
    ),
    (
        "network",
        (
            "requests",
            "httpx",
            "urllib",
            "aiohttp",
            "http.client",
            "socket",
            "urllib3",
            "grpc",
            "websockets",
        ),
        re.compile(r"^(requests|httpx|urllib\.request|aiohttp|socket)\."),
    ),
    (
        "filesystem",
        ("shutil", "tempfile", "glob", "zipfile", "tarfile"),
        re.compile(
            r"^(open|os\.(remove|unlink|rmdir|makedirs|rename|replace|chmod|chown|walk)|"
            r"shutil\.\w+|\w*\.(write_text|write_bytes|read_text|read_bytes|unlink|rmdir|"
            r"mkdir|rename|resolve|extractall))$"
        ),
    ),
    (
        "deserialization",
        ("pickle", "marshal", "shelve", "dill", "jsonpickle", "yaml"),
        re.compile(
            r"^(pickle|marshal|dill|jsonpickle|shelve)\.\w+$|^yaml\.(load|unsafe_load|load_all)$"
            r"|^(eval|exec)$"
        ),
    ),
    (
        "auth",
        ("flask_login", "django.contrib.auth", "authlib", "oauthlib"),
        re.compile(
            r"(auth|permission|perm|role|login|logout|is_admin|access|privilege|csrf|"
            r"session|token)",
            re.I,
        ),
    ),
    (
        "input_validation",
        ("pydantic", "marshmallow", "cerberus", "jsonschema", "voluptuous"),
        re.compile(r"(validat|sanitiz|clean_|escape|quote|is_valid|fullmatch)", re.I),
    ),
    (
        "concurrency",
        ("threading", "multiprocessing", "asyncio", "concurrent", "tenacity", "backoff", "celery"),
        re.compile(r"(retry|backoff|Lock|Semaphore|idempot|acquire|release)", re.I),
    ),
    ("migrations", ("alembic", "django.db.migrations"), None),
)

# Function/class names that mark an auth surface even without calls.
_AUTH_NAME = re.compile(
    r"(auth|permission|authori[sz]e|login|is_admin|require_role|access_control)", re.I
)


@dataclass(slots=True)
class SurfaceHit:
    surface: str
    file: str
    reason: str

    def to_json(self) -> dict[str, str]:
        return {"surface": self.surface, "file": self.file, "reason": self.reason}


@dataclass(slots=True)
class RiskAssessment:
    level: RiskLevel
    hits: list[SurfaceHit] = field(default_factory=list)

    @property
    def surfaces(self) -> list[str]:
        return sorted({h.surface for h in self.hits})

    def to_json(self) -> dict[str, object]:
        return {
            "level": self.level.name,
            "surfaces": self.surfaces,
            "evidence": [h.to_json() for h in self.hits],
        }


def _module_imports(module: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(module):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def _changed_nodes(module: ast.Module, lines: set[int] | None) -> list[ast.AST]:
    """Functions touched by ``lines`` plus touched module-level statements.

    ``lines=None`` means the whole file is new (or deleted).
    """
    if lines is None:
        return [module]
    nodes: list[ast.AST] = [i.node for i in iter_functions(module) if touches(i.node, lines)]
    for stmt in module.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if isinstance(stmt, ast.ClassDef):
            # class-level statements (attributes, decorators), not methods
            for sub in stmt.body:
                if not isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)) and touches(
                    sub, lines
                ):
                    nodes.append(sub)
            continue
        if touches(stmt, lines):
            nodes.append(stmt)
    return nodes


def _ast_hits(path: str, module: ast.Module, lines: set[int] | None, side: str) -> list[SurfaceHit]:
    hits: list[SurfaceHit] = []
    imports = _module_imports(module)
    changed = _changed_nodes(module, lines)
    if not changed:
        return hits
    called: set[str] = set()
    defined: set[str] = set()
    touched_imports: set[str] = set()
    for node in changed:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                called.add(call_name(sub))
            elif isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                defined.add(sub.name)
                for d in sub.decorator_list:
                    called.add(dotted(d.func if isinstance(d, ast.Call) else d))
            elif isinstance(sub, ast.Import):
                touched_imports.update(a.name for a in sub.names)
            elif isinstance(sub, ast.ImportFrom) and sub.module:
                touched_imports.add(sub.module)
    for surface, prefixes, call_re in AST_RULES:
        imp = sorted(
            m for m in touched_imports if any(m == p or m.startswith(p + ".") for p in prefixes)
        )
        if imp:
            hits.append(SurfaceHit(surface, path, f"{side}: changed import of {imp[0]}"))
            continue
        if call_re is None:
            continue
        uses_module = any(any(m == p or m.startswith(p + ".") for p in prefixes) for m in imports)
        for name in sorted(called):
            if not name or not call_re.search(name):
                continue
            # Generic call names (open, sign...) count only if the module is imported or the
            # call is qualified by a known module.
            if surface in ("auth", "input_validation", "concurrency") or uses_module or "." in name:
                hits.append(SurfaceHit(surface, path, f"{side}: changed code calls {name}()"))
                break
    for name in sorted(defined):
        if _AUTH_NAME.search(name):
            hits.append(SurfaceHit("auth", path, f"{side}: changed definition {name}"))
            break
    return hits


def assess(ctx: PatchContext, policy_repo_path: str | None) -> RiskAssessment:
    hits: list[SurfaceHit] = []
    for fc in ctx.patch.files:
        hits.extend(_file_hits(ctx, fc, policy_repo_path))
    # de-duplicate (surface, file) keeping the first reason
    seen: set[tuple[str, str]] = set()
    unique: list[SurfaceHit] = []
    for h in sorted(hits, key=lambda h: (h.file, h.surface, h.reason)):
        if (h.surface, h.file) not in seen:
            seen.add((h.surface, h.file))
            unique.append(h)
    level = max((SURFACE_RISK.get(h.surface, RiskLevel.LOW) for h in unique), default=RiskLevel.LOW)
    return RiskAssessment(level, unique)


def _file_hits(ctx: PatchContext, fc: FileChange, policy_repo_path: str | None) -> list[SurfaceHit]:
    hits: list[SurfaceHit] = []
    for p in fc.paths:
        if policy_repo_path is not None and p == policy_repo_path:
            hits.append(SurfaceHit("gate_policy", p, "patch modifies the review contract"))
        if is_test_path(p):
            hits.append(SurfaceHit("tests", p, "test path"))
        for surface, patterns in PATH_RULES:
            pat = match_any(p, patterns)
            if pat:
                hits.append(SurfaceHit(surface, p, f"path matches {pat}"))
    if fc.binary:
        return hits
    if fc.new_path and fc.new_path.endswith(".py"):
        mod = ctx.head_ast(fc)
        if mod is not None:
            lines = None if fc.status == "A" else set(fc.added)
            hits.extend(_ast_hits(fc.path, mod, lines, "head"))
    if fc.old_path and fc.old_path.endswith(".py"):
        mod = ctx.base_ast(fc)
        if mod is not None:
            lines = None if fc.status == "D" else set(fc.removed)
            hits.extend(_ast_hits(fc.path, mod, lines, "base"))
    return hits
