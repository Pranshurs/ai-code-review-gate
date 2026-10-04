"""Dependency delta between base and head, evaluated against the contract.

Vulnerability data is deliberately *not* reimplemented: run ``pip-audit`` /
``osv-scanner`` / GitHub dependency-review as required checks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PurePosixPath

from aicrg.analysis.context import PatchContext
from aicrg.dependencies.manifests import (
    LOCKFILES,
    Dep,
    ManifestError,
    is_manifest,
    parse_manifest,
)
from aicrg.model import Finding, Severity
from aicrg.rules import finding

# A small, static list used only for near-miss name detection. Not a reputation
# database; a near miss yields REVIEW_REQUIRED, never an automatic verdict.
POPULAR = {
    "python": [
        "requests",
        "urllib3",
        "certifi",
        "idna",
        "charset-normalizer",
        "setuptools",
        "wheel",
        "pip",
        "six",
        "python-dateutil",
        "pyyaml",
        "numpy",
        "pandas",
        "boto3",
        "botocore",
        "s3transfer",
        "packaging",
        "typing-extensions",
        "attrs",
        "cryptography",
        "cffi",
        "pycparser",
        "jinja2",
        "markupsafe",
        "click",
        "pydantic",
        "pydantic-core",
        "protobuf",
        "grpcio",
        "rsa",
        "pyasn1",
        "google-auth",
        "cachetools",
        "jmespath",
        "pytz",
        "tzdata",
        "colorama",
        "filelock",
        "platformdirs",
        "virtualenv",
        "importlib-metadata",
        "zipp",
        "pluggy",
        "pytest",
        "iniconfig",
        "tomli",
        "exceptiongroup",
        "aiohttp",
        "yarl",
        "multidict",
        "frozenlist",
        "aiosignal",
        "async-timeout",
        "sqlalchemy",
        "greenlet",
        "psutil",
        "pillow",
        "scipy",
        "matplotlib",
        "wrapt",
        "decorator",
        "pyjwt",
        "jsonschema",
        "requests-oauthlib",
        "oauthlib",
        "werkzeug",
        "flask",
        "django",
        "fastapi",
        "starlette",
        "uvicorn",
        "httpx",
        "httpcore",
        "anyio",
        "sniffio",
        "h11",
        "rich",
        "pygments",
        "tqdm",
        "docutils",
        "lxml",
        "beautifulsoup4",
        "soupsieve",
        "openpyxl",
        "et-xmlfile",
        "paramiko",
        "pynacl",
        "bcrypt",
        "redis",
        "celery",
        "kombu",
        "billiard",
        "vine",
        "psycopg2",
        "psycopg2-binary",
        "pymysql",
        "mypy",
        "ruff",
        "black",
        "isort",
        "flake8",
        "pylint",
        "coverage",
        "tox",
        "nox",
        "scikit-learn",
        "joblib",
        "threadpoolctl",
        "torch",
        "tensorflow",
        "keras",
        "transformers",
        "tokenizers",
        "huggingface-hub",
        "safetensors",
        "regex",
        "openai",
        "anthropic",
        "langchain",
        "tenacity",
        "marshmallow",
        "gunicorn",
        "alembic",
        "mako",
        "pyparsing",
        "markdown",
        "toml",
        "tomlkit",
        "simplejson",
        "ujson",
        "orjson",
        "msgpack",
        "python-dotenv",
        "dnspython",
        "email-validator",
        "passlib",
        "itsdangerous",
        "boto",
        "awscli",
        "google-cloud-storage",
        "azure-core",
        "azure-storage-blob",
        "docker",
        "kubernetes",
        "sentry-sdk",
        "structlog",
        "loguru",
        "arrow",
        "pendulum",
        "babel",
        "sphinx",
    ],
    "npm": [
        "react",
        "react-dom",
        "lodash",
        "express",
        "axios",
        "chalk",
        "commander",
        "debug",
        "moment",
        "request",
        "typescript",
        "webpack",
        "babel-core",
        "eslint",
        "prettier",
        "jest",
        "mocha",
        "vue",
        "next",
        "uuid",
        "dotenv",
        "cross-env",
        "rimraf",
        "glob",
        "minimist",
        "yargs",
        "semver",
        "colors",
        "async",
        "underscore",
        "jquery",
        "body-parser",
        "cors",
        "jsonwebtoken",
        "bcrypt",
        "mongoose",
        "redis",
        "ws",
        "socket.io",
        "node-fetch",
        "tslib",
        "rxjs",
        "zod",
    ],
}


def _distance(a: str, b: str, limit: int = 2) -> int:
    """Optimal string alignment distance, early-exit above ``limit``."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


def near_miss(name: str, ecosystem: str) -> str | None:
    popular = POPULAR.get(ecosystem, [])
    if name in popular or len(name) < 4:
        return None
    squashed = name.replace("-", "").replace("_", "")
    for p in popular:
        if squashed == p.replace("-", "") and name != p:
            return p
        limit = 1 if len(p) < 9 else 2
        if _distance(name, p, limit) <= limit:
            return p
        for affix in ("python-", "py", "-python", "-py"):
            if name in (affix + p, p + affix) and len(p) > 4:
                return p
    return None


@dataclass(slots=True)
class DependencyChange:
    change: str  # added | removed | changed
    before: Dep | None
    after: Dep | None

    def to_json(self) -> dict[str, object]:
        ref = self.after or self.before
        if ref is None:
            raise ValueError("dependency change without either side")
        return {
            "change": self.change,
            "ecosystem": ref.ecosystem,
            "name": ref.name,
            "kind": ref.kind,
            "before": self.before.spec if self.before else None,
            "after": self.after.spec if self.after else None,
            "source": ref.source,
        }


@dataclass(slots=True)
class DependencyReport:
    changes: list[DependencyChange] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def to_json(self) -> list[dict[str, object]]:
        return [c.to_json() for c in self.changes]


def analyze_dependencies(ctx: PatchContext) -> DependencyReport:
    c = ctx.contract
    dp = c.dependency_policy
    report = DependencyReport()
    before: dict[tuple[str, str], Dep] = {}
    after: dict[tuple[str, str], Dep] = {}
    index_before: list[str] = []
    index_after: list[str] = []
    manifest_dirs: dict[str, set[str]] = {}  # ecosystem -> dirs whose manifest deps changed
    changed_paths = {p for fc in ctx.patch.files for p in fc.paths}
    for fc in ctx.patch.files:
        if not any(is_manifest(p) for p in fc.paths):
            continue
        try:
            deps_b, ib = parse_manifest(fc.old_path, ctx.base_text(fc)) if fc.old_path else ([], [])
            deps_a, ia = parse_manifest(fc.new_path, ctx.head_text(fc)) if fc.new_path else ([], [])
        except ManifestError as exc:
            report.findings.append(
                finding("dependency_manifest_unparseable", c, str(exc), file=fc.path)
            )
            continue
        index_before += ib
        index_after += ia
        for d in deps_b:
            before.setdefault((d.ecosystem, d.name), d)
        for d in deps_a:
            after.setdefault((d.ecosystem, d.name), d)
        if {(d.ecosystem, d.name, d.spec, d.kind) for d in deps_b} != {
            (d.ecosystem, d.name, d.spec, d.kind) for d in deps_a
        }:
            for d in [*deps_a, *deps_b]:
                manifest_dirs.setdefault(d.ecosystem, set()).add(str(PurePosixPath(fc.path).parent))

    new_count = 0
    for key in sorted(set(before) | set(after)):
        b, a = before.get(key), after.get(key)
        if b is None and a is not None:
            report.changes.append(DependencyChange("added", None, a))
            new_count += 1
            _added(ctx, report, a)
        elif a is None and b is not None:
            report.changes.append(DependencyChange("removed", b, None))
            report.findings.append(
                finding("dependency_removed", c, f"{b.name} removed ({b.kind})", file=b.source)
            )
        elif a is not None and b is not None and (a.spec != b.spec or a.kind != b.kind):
            report.changes.append(DependencyChange("changed", b, a))
            if b.kind != "runtime" and a.kind == "runtime":
                _added(ctx, report, a, promoted=True)
            elif a.direct_url and not b.direct_url:
                _direct_url(ctx, report, a)
            elif dp.require_pinned_versions and b.pinned and not a.pinned:
                report.findings.append(
                    finding(
                        "unpinned_dependency",
                        c,
                        f"{a.name} no longer pinned: {b.spec} -> {a.spec}",
                        file=a.source,
                        severity=Severity.BLOCK,
                    )
                )

    if new_count > dp.max_new_dependencies:
        report.findings.append(
            finding(
                "dependency_expansion",
                c,
                f"{new_count} new dependencies (max {dp.max_new_dependencies})",
            )
        )
    for opt in sorted(set(index_after) - set(index_before)):
        report.findings.append(
            finding("package_index_changed", c, f"package source option added: {opt}")
        )

    for eco, dirs in sorted(manifest_dirs.items()):
        for dirname in sorted(dirs):
            for lock in LOCKFILES[eco]:
                lock_path = lock if dirname in ("", ".") else f"{dirname}/{lock}"
                if lock_path in changed_paths:
                    break
                if ctx.repo.read_blob(ctx.patch.head, lock_path) is not None:
                    report.findings.append(
                        finding(
                            "lockfile_not_updated",
                            c,
                            f"dependencies changed in {dirname or '.'} but {lock_path} "
                            "was not updated",
                            file=lock_path,
                        )
                    )
                    break
    return report


def _direct_url(ctx: PatchContext, report: DependencyReport, d: Dep) -> None:
    sev = (
        Severity.ADVISORY
        if ctx.contract.dependency_policy.allow_direct_url_dependencies
        else (Severity.BLOCK)
    )
    report.findings.append(
        finding(
            "direct_url_dependency",
            ctx.contract,
            f"{d.name} installed from {d.spec}",
            file=d.source,
            severity=sev,
        )
    )


def _added(ctx: PatchContext, report: DependencyReport, d: Dep, promoted: bool = False) -> None:
    c = ctx.contract
    dp = c.dependency_policy
    allowed = d.name in dp.allowed_new_dependencies
    verb = "promoted to runtime" if promoted else "added"
    if d.kind == "runtime":
        sev = (
            Severity.ADVISORY if (allowed or dp.allow_new_runtime_dependencies) else Severity.BLOCK
        )
        report.findings.append(
            finding(
                "new_runtime_dependency",
                c,
                f"runtime dependency {d.name} {verb}"
                + (
                    ""
                    if sev is Severity.ADVISORY
                    else " (contract disallows new runtime dependencies)"
                ),
                file=d.source,
                after=f"{d.name} {d.spec}".strip(),
                severity=sev,
            )
        )
    else:
        sev = Severity.ADVISORY if (allowed or dp.allow_new_dev_dependencies) else Severity.BLOCK
        report.findings.append(
            finding(
                "new_dev_dependency",
                c,
                f"{d.kind} dependency {d.name} added",
                file=d.source,
                after=f"{d.name} {d.spec}".strip(),
                severity=sev,
            )
        )
    if d.direct_url:
        _direct_url(ctx, report, d)
    elif dp.require_pinned_versions and not d.pinned:
        report.findings.append(
            finding(
                "unpinned_dependency",
                c,
                f"{d.name} is not pinned to an exact version ({d.spec or 'any'})",
                file=d.source,
                severity=Severity.BLOCK,
            )
        )
    target = near_miss(d.name, d.ecosystem)
    if target:
        report.findings.append(
            finding(
                "suspicious_package_name",
                c,
                f"`{d.name}` is a near miss of popular package `{target}`",
                file=d.source,
                after=d.name,
            )
        )
