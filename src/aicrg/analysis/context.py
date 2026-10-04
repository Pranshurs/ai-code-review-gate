"""Shared, cached view of a patch for analysers."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from aicrg.analysis.pyast import parse_python
from aicrg.git.diff import FileChange, Patch
from aicrg.git.repo import Repo
from aicrg.globmatch import match_any
from aicrg.policy.contract import ReviewContract

TEST_PATH_PATTERNS = (
    "tests/**",
    "test/**",
    "**/tests/**",
    "**/test/**",
    "test_*.py",
    "*_test.py",
    "conftest.py",
)


def is_test_path(path: str) -> bool:
    return match_any(path, TEST_PATH_PATTERNS) is not None


def is_python(path: str | None) -> bool:
    return bool(path) and str(path).endswith((".py", ".pyi"))


def _module_names(path: str) -> set[str]:
    """Dotted names a file can be imported as (any suffix of its path, src-layout safe)."""
    parts = path[: -len(".py")].split("/") if path.endswith(".py") else path.split("/")
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return {".".join(parts[i:]) for i in range(len(parts)) if parts[i:]}


def _imported_modules(tree: ast.Module, importer: str) -> set[str]:
    pkg = importer.split("/")[:-1]
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = pkg[: len(pkg) - (node.level - 1)] if node.level > 1 else pkg
                mod = ".".join([*base, *(node.module.split(".") if node.module else [])])
            else:
                mod = node.module or ""
            if mod:
                found.add(mod)
            found.update(f"{mod}.{a.name}" if mod else a.name for a in node.names)
    return found


def imported_by_production(repo: Repo, commit: str, path: str) -> bool:
    """True if a non-test Python file at ``commit`` imports the module at ``path``.

    A file named like a test (``test_x.py``, ``x_test.py``, under ``test/``) that
    production code imports *is* production code, whatever its name says.
    """
    names = _module_names(path)
    stem = path.rsplit("/", 1)[-1].removesuffix(".py")
    if stem == "__init__":
        stem = path.rsplit("/", 2)[-2] if path.count("/") else stem
    out = repo.git("grep", "-l", "-F", "-e", stem, commit, "--", "*.py", check=False)
    for line in out.decode("utf-8", "replace").splitlines():
        importer = line.split(":", 1)[1] if ":" in line else line
        if importer == path or is_test_path(importer):
            continue
        tree = parse_python(repo.read_blob(commit, importer))
        if tree is None:
            continue
        mods = _imported_modules(tree, importer)
        if mods & names:
            return True
    return False


def is_production_path(repo: Repo, commit: str, path: str) -> bool:
    return not is_test_path(path) or imported_by_production(repo, commit, path)


@dataclass
class PatchContext:
    repo: Repo
    patch: Patch
    contract: ReviewContract
    _base: dict[str, bytes | None] = field(default_factory=dict)
    _head: dict[str, bytes | None] = field(default_factory=dict)
    _base_ast: dict[str, ast.Module | None] = field(default_factory=dict)
    _head_ast: dict[str, ast.Module | None] = field(default_factory=dict)
    _prod: dict[tuple[str, str], bool] = field(default_factory=dict)

    def base_bytes(self, fc: FileChange) -> bytes | None:
        if fc.old_path is None:
            return None
        if fc.old_path not in self._base:
            self._base[fc.old_path] = self.repo.read_blob(self.patch.base, fc.old_path)
        return self._base[fc.old_path]

    def head_bytes(self, fc: FileChange) -> bytes | None:
        if fc.new_path is None:
            return None
        if fc.new_path not in self._head:
            self._head[fc.new_path] = self.repo.read_blob(self.patch.head, fc.new_path)
        return self._head[fc.new_path]

    def base_text(self, fc: FileChange) -> str | None:
        data = self.base_bytes(fc)
        return None if data is None or b"\0" in data else data.decode("utf-8", "replace")

    def head_text(self, fc: FileChange) -> str | None:
        data = self.head_bytes(fc)
        return None if data is None or b"\0" in data else data.decode("utf-8", "replace")

    def base_ast(self, fc: FileChange) -> ast.Module | None:
        key = fc.old_path or ""
        if key not in self._base_ast:
            self._base_ast[key] = parse_python(self.base_bytes(fc)) if is_python(key) else None
        return self._base_ast[key]

    def head_ast(self, fc: FileChange) -> ast.Module | None:
        key = fc.new_path or ""
        if key not in self._head_ast:
            self._head_ast[key] = parse_python(self.head_bytes(fc)) if is_python(key) else None
        return self._head_ast[key]

    def is_production(self, path: str, side: str = "head") -> bool:
        commit = self.patch.head if side == "head" else self.patch.base
        key = (side, path)
        if key not in self._prod:
            self._prod[key] = is_production_path(self.repo, commit, path)
        return self._prod[key]

    def python_files(self) -> list[FileChange]:
        return [f for f in self.patch.files if is_python(f.old_path) or is_python(f.new_path)]
