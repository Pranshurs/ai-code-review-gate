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


@dataclass
class PatchContext:
    repo: Repo
    patch: Patch
    contract: ReviewContract
    _base: dict[str, bytes | None] = field(default_factory=dict)
    _head: dict[str, bytes | None] = field(default_factory=dict)
    _base_ast: dict[str, ast.Module | None] = field(default_factory=dict)
    _head_ast: dict[str, ast.Module | None] = field(default_factory=dict)

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

    def python_files(self) -> list[FileChange]:
        return [f for f in self.patch.files if is_python(f.old_path) or is_python(f.new_path)]
