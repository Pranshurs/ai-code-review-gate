"""Shared, cached view of a patch for analysers."""

from __future__ import annotations

import ast
import re
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


_CONFIG_SUFFIXES = (".toml", ".cfg", ".ini", ".yaml", ".yml", ".json")


def _string_refs(tree: ast.Module) -> set[str]:
    """String constants that could name a module (importlib/__import__/entry points)."""
    refs: set[str] = set()
    for node in ast.walk(tree):
        v = _const_str(node)
        if v is not None and len(v) < 300:
            v = v.strip()
            refs.add(v)
            refs.add(v.split(":", 1)[0])  # "pkg.mod:func" entry-point form
    return refs


def _const_str(node: ast.AST) -> str | None:
    """A string constant, or a `+` concatenation of string constants ('a.' + 'b')."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _const_str(node.left), _const_str(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def imported_by_production(repo: Repo, commit: str, path: str) -> bool:
    """True if non-test code at ``commit`` imports or names the module at ``path``.

    A file named like a test (``test_x.py``, ``x_test.py``, under ``test/``) that
    production code uses *is* production code, whatever its name says. "Uses"
    covers static imports, string references in non-test Python
    (``importlib.import_module("pkg.x")``, ``__import__``) and entry points in
    packaging/config files (``pkg.x:main``). Module names computed at run time
    from fragments are not resolved.
    """
    names = _module_names(path)
    dotted = {n for n in names if "." in n}
    stem = path.rsplit("/", 1)[-1].removesuffix(".py")
    if stem == "__init__":
        stem = path.rsplit("/", 2)[-2] if path.count("/") else stem
    out = repo.git("grep", "-l", "-F", "-e", stem, commit, check=False)
    # Dynamic importers may build the name from fragments the stem search cannot see.
    out += b"\n" + repo.git(
        "grep",
        "-l",
        "-F",
        "-e",
        "import_module",
        "-e",
        "__import__",
        commit,
        "--",
        "*.py",
        check=False,
    )
    for line in sorted(set(out.decode("utf-8", "replace").splitlines()) - {""}):
        ref = line.split(":", 1)[1] if ":" in line else line
        if ref == path or is_test_path(ref):
            continue
        if ref.endswith(".py"):
            tree = parse_python(repo.read_blob(commit, ref))
            if tree is None:
                continue
            if (_imported_modules(tree, ref) | _string_refs(tree)) & names:
                return True
        elif ref.endswith(_CONFIG_SUFFIXES):
            text = (repo.read_blob(commit, ref) or b"").decode("utf-8", "replace")
            for name in dotted:
                if re.search(rf"(?<![\w.]){re.escape(name)}(?![\w])", text):
                    return True
            if re.search(rf"(?<![\w.]){re.escape(stem)}\s*:\s*\w", text):
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
