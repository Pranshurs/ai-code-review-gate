"""Small Python AST helpers shared by the risk, test-integrity and security stages."""

from __future__ import annotations

import ast
import warnings
from collections.abc import Iterator
from dataclasses import dataclass

FuncNode = ast.FunctionDef | ast.AsyncFunctionDef

MAX_SOURCE_BYTES = 2_000_000


def parse_python(data: bytes | None) -> ast.Module | None:
    """Parse source; ``None`` for missing, binary, oversized or invalid input."""
    if data is None or b"\0" in data or len(data) > MAX_SOURCE_BYTES:
        return None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return ast.parse(data.decode("utf-8"))
    except (SyntaxError, UnicodeDecodeError, ValueError, RecursionError):
        return None


def dotted(node: ast.AST) -> str:
    """Best-effort dotted name: ``a.b.c`` for attribute chains, ``''`` otherwise."""
    parts: list[str] = []
    cur: ast.AST = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    elif isinstance(cur, ast.Call):
        inner = dotted(cur.func)
        if inner:
            parts.append(inner + "()")
    else:
        return ""
    return ".".join(reversed(parts))


def call_name(call: ast.Call) -> str:
    return dotted(call.func)


def last_segment(name: str) -> str:
    return name.rsplit(".", 1)[-1]


@dataclass(frozen=True, slots=True)
class FunctionInfo:
    qualname: str
    node: FuncNode
    class_name: str | None


def iter_functions(module: ast.Module) -> Iterator[FunctionInfo]:
    """All function/method definitions with a stable qualified name."""

    def walk(body: list[ast.stmt], prefix: str, cls: str | None) -> Iterator[FunctionInfo]:
        for stmt in body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                q = f"{prefix}{stmt.name}"
                yield FunctionInfo(q, stmt, cls)
                yield from walk(stmt.body, q + ".<locals>.", None)
            elif isinstance(stmt, ast.ClassDef):
                yield from walk(stmt.body, f"{prefix}{stmt.name}.", stmt.name)
            elif isinstance(stmt, (ast.If, ast.Try, ast.With)):
                # Conditionally defined functions keep their plain name.
                for sub in ("body", "orelse", "finalbody", "handlers"):
                    block = getattr(stmt, sub, None)
                    if isinstance(block, list):
                        stmts: list[ast.stmt] = []
                        for item in block:
                            if isinstance(item, ast.ExceptHandler):
                                stmts.extend(item.body)
                            elif isinstance(item, ast.stmt):
                                stmts.append(item)
                        yield from walk(stmts, prefix, cls)

    yield from walk(module.body, "", None)


def functions_by_name(module: ast.Module | None) -> dict[str, FuncNode]:
    if module is None:
        return {}
    out: dict[str, FuncNode] = {}
    for info in iter_functions(module):
        out.setdefault(info.qualname, info.node)
    return out


def span(node: ast.AST) -> tuple[int, int]:
    start = getattr(node, "lineno", 0)
    decos = getattr(node, "decorator_list", [])
    if decos:
        start = min([start, *(d.lineno for d in decos)])
    end = getattr(node, "end_lineno", None) or start
    return start, end


def touches(node: ast.AST, lines: set[int]) -> bool:
    if not lines:
        return False
    lo, hi = span(node)
    return any(lo <= ln <= hi for ln in lines)


def unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:  # pragma: no cover - ast.unparse is total on parsed trees
        return ast.dump(node)


def const_value(node: ast.AST | None) -> object:
    """Literal value of a constant node, else a sentinel."""
    if isinstance(node, ast.Constant):
        return node.value
    return _NOT_CONST


class _NotConst:
    def __repr__(self) -> str:
        return "<non-constant>"


_NOT_CONST = _NotConst()
NOT_CONST = _NOT_CONST


def is_dynamic_string(node: ast.AST) -> bool:
    """True if the expression builds a string from non-literal parts."""
    if isinstance(node, ast.Constant):
        return False
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    # argv lists/tuples are not shell-interpreted by subprocess
    return not isinstance(node, (ast.List, ast.Tuple))
