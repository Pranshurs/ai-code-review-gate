"""Diff-scoped mutant generation for Python.

This is deliberately small. It is not a general mutation-testing framework:
it only generates *first-order* mutants on lines the patch added to production
code, so the cost scales with the patch, not the repository.

Operators (each yields one mutant per site):

=====================  =====================================================
compare                ``<``/``<=``, ``>``/``>=``, ``==``/``!=``, ``is``/``is not``,
                       ``in``/``not in`` swapped
boolop                 ``and`` <-> ``or``
not                    ``not x`` -> ``x``
if_negate              ``if c:`` / ``while c:`` / ``x if c else y`` -> ``not c``
constant_bool          ``True`` <-> ``False``
constant_number        ``n`` -> ``n + 1`` (``0`` -> ``1``, ``1`` -> ``0``)
constant_string        string used in a comparison or returned -> ``"aicrg-mutant"``
arith                  ``+``<->``-``, ``*``<->``/``, ``//``->``/``, ``%``->``*``
return_none            ``return <expr>`` -> ``return None``
raise_pass             ``raise ...`` -> ``pass`` (a guard that no longer rejects)
=====================  =====================================================

Edits are applied to the exact source span of the mutated node (expression
replacements are parenthesised), so the rest of the file is byte-identical.
A mutant whose compiled bytecode equals the original is *equivalent by
construction* and is not run. Lines carrying ``# pragma: no mutate`` or
``# aicrg: no-mutate`` are skipped and reported.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import random
from collections.abc import Iterator
from dataclasses import dataclass
from types import CodeType

PRAGMAS = ("pragma: no mutate", "aicrg: no-mutate")
STRING_SENTINEL = "aicrg-mutant"

_CMP_SWAP: dict[type[ast.cmpop], type[ast.cmpop]] = {
    ast.Lt: ast.LtE,
    ast.LtE: ast.Lt,
    ast.Gt: ast.GtE,
    ast.GtE: ast.Gt,
    ast.Eq: ast.NotEq,
    ast.NotEq: ast.Eq,
    ast.Is: ast.IsNot,
    ast.IsNot: ast.Is,
    ast.In: ast.NotIn,
    ast.NotIn: ast.In,
}
_ARITH_SWAP: dict[type[ast.operator], type[ast.operator]] = {
    ast.Add: ast.Sub,
    ast.Sub: ast.Add,
    ast.Mult: ast.Div,
    ast.Div: ast.Mult,
    ast.FloorDiv: ast.Div,
    ast.Mod: ast.Mult,
}


@dataclass(frozen=True, slots=True)
class Mutant:
    id: str
    file: str
    line: int
    operator: str
    before: str
    after: str
    source: bytes  # whole mutated file


@dataclass(slots=True)
class Generation:
    mutants: list[Mutant]
    equivalent: list[Mutant]
    suppressed_lines: list[int]
    sites: int
    parse_error: str | None = None


def _line_offsets(src: bytes) -> list[int]:
    offs = [0]
    for i, b in enumerate(src):
        if b == 0x0A:
            offs.append(i + 1)
    return offs


def _span(node: ast.AST, offs: list[int]) -> tuple[int, int]:
    start = offs[node.lineno - 1] + node.col_offset  # type: ignore[attr-defined]
    end = offs[node.end_lineno - 1] + node.end_col_offset  # type: ignore[attr-defined]
    return start, end


def _fingerprint(code: CodeType) -> tuple[object, ...]:
    consts = tuple(
        _fingerprint(c) if isinstance(c, CodeType) else (type(c).__name__, repr(c))
        for c in code.co_consts
    )
    return (
        code.co_code,
        consts,
        code.co_names,
        code.co_varnames,
        code.co_freevars,
        code.co_cellvars,
    )


def _compiled(src: bytes, path: str) -> tuple[object, ...] | None:
    try:
        return _fingerprint(compile(src, path, "exec", dont_inherit=True))
    except (SyntaxError, ValueError):
        return None


def _string_sites(tree: ast.Module) -> set[int]:
    """ids of string constants that sit in a comparison or a return value."""
    ids: set[int] = set()

    def strings(n: ast.AST) -> Iterator[ast.Constant]:
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            yield n
        elif isinstance(n, ast.Set | ast.List | ast.Tuple):
            for e in n.elts:
                yield from strings(e)

    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            for operand in (node.left, *node.comparators):
                ids.update(id(c) for c in strings(operand))
        elif isinstance(node, ast.Return) and node.value is not None:
            ids.update(id(c) for c in strings(node.value))
    return ids


def _docstring_ids(tree: ast.Module) -> set[int]:
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                ids.add(id(body[0].value))
    return ids


def _candidates(tree: ast.Module) -> Iterator[tuple[ast.AST, str, str]]:
    """(node to replace, operator name, replacement text) for every mutation site."""
    strings = _string_sites(tree)
    docstrings = _docstring_ids(tree)
    annotations: set[int] = set()
    for node in ast.walk(tree):
        for ann in (getattr(node, "annotation", None), getattr(node, "returns", None)):
            if isinstance(ann, ast.AST):
                annotations.update(id(n) for n in ast.walk(ann))
        if isinstance(node, ast.JoinedStr):
            # f-string internals have unreliable source positions before Python 3.12.
            annotations.update(id(n) for n in ast.walk(node))
    for node in ast.walk(tree):
        if id(node) in annotations:
            continue
        if isinstance(node, ast.Compare):
            for i, op in enumerate(node.ops):
                swap = _CMP_SWAP.get(type(op))
                if swap is not None:
                    new = copy.deepcopy(node)
                    new.ops[i] = swap()
                    yield node, "compare", f"({ast.unparse(new)})"
        elif isinstance(node, ast.BoolOp):
            new_b = copy.deepcopy(node)
            new_b.op = ast.Or() if isinstance(node.op, ast.And) else ast.And()
            yield node, "boolop", f"({ast.unparse(new_b)})"
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            yield node, "not", f"({ast.unparse(node.operand)})"
        elif isinstance(node, ast.BinOp):
            swap_a = _ARITH_SWAP.get(type(node.op))
            if swap_a is not None:
                new_a = copy.deepcopy(node)
                new_a.op = swap_a()
                yield node, "arith", f"({ast.unparse(new_a)})"
        elif isinstance(node, ast.Constant) and id(node) not in docstrings:
            v = node.value
            if isinstance(v, bool):
                yield node, "constant_bool", repr(not v)
            elif isinstance(v, int | float) and not isinstance(v, bool):
                nv = 1 if v == 0 else (0 if v == 1 else v + 1)
                yield node, "constant_number", repr(nv)
            elif isinstance(v, str) and id(node) in strings and v != STRING_SENTINEL:
                yield node, "constant_string", repr(STRING_SENTINEL)
        if isinstance(node, ast.If | ast.While | ast.IfExp):
            yield node.test, "if_negate", f"(not ({ast.unparse(node.test)}))"
        if (
            isinstance(node, ast.Return)
            and node.value is not None
            and not (isinstance(node.value, ast.Constant) and node.value.value is None)
        ):
            yield node, "return_none", "return None"
        if isinstance(node, ast.Raise):
            yield node, "raise_pass", "pass"


def generate(path: str, src: bytes, changed_lines: set[int]) -> Generation:
    """Mutants for ``changed_lines`` of one file. Unparseable files report ``parse_error``."""
    try:
        tree = ast.parse(src, path)
    except (SyntaxError, ValueError) as exc:
        return Generation([], [], [], 0, parse_error=f"{type(exc).__name__}: {exc}")
    offs = _line_offsets(src)
    lines = src.decode("utf-8", "replace").splitlines()
    suppressed = sorted(
        ln
        for ln in changed_lines
        if 0 < ln <= len(lines) and any(p in lines[ln - 1] for p in PRAGMAS)
    )
    original = _compiled(src, path)
    seen: set[bytes] = set()
    mutants: list[Mutant] = []
    equivalent: list[Mutant] = []
    sites = 0
    cands = sorted(
        _candidates(tree),
        key=lambda c: (c[0].lineno, c[0].col_offset, c[1], c[2]),  # type: ignore[attr-defined]
    )
    for node, op, replacement in cands:
        line = node.lineno  # type: ignore[attr-defined]
        if line not in changed_lines or line in suppressed:
            continue
        start, end = _span(node, offs)
        before = src[start:end].decode("utf-8", "replace")
        new_src = src[:start] + replacement.encode() + src[end:]
        if new_src in seen or new_src == src:
            continue
        seen.add(new_src)
        compiled = _compiled(new_src, path)
        if compiled is None:
            continue  # a replacement that does not compile is not a mutant
        sites += 1
        mid = hashlib.sha256(f"{path}:{line}:{start}:{op}:{replacement}".encode()).hexdigest()[:12]
        m = Mutant(mid, path, line, op, before[:200], replacement[:200], new_src)
        (equivalent if compiled == original else mutants).append(m)
    return Generation(mutants, equivalent, suppressed, sites)


def sample(mutants: list[Mutant], limit: int, seed: int) -> list[Mutant]:
    """Random subset drawn with ``seed`` (recorded in the receipt, so reproducible).

    The seed is chosen per run, so a patch cannot predict which mutants will be
    run and hide its weak spot outside an evenly spaced, deterministic sample.
    """
    if len(mutants) <= limit:
        return list(mutants)
    picked = random.Random(seed).sample(range(len(mutants)), limit)  # noqa: S311 - not crypto
    return [mutants[i] for i in sorted(picked)]


CONTROL_NAME = "_aicrg_potency_control"
CONTROL_SUFFIX = f"\n{CONTROL_NAME} = None  # aicrg potency control: behaviour unchanged\n".encode()


def _function_controls(path: str, src: bytes, lines: set[int]) -> list[Mutant]:
    try:
        tree = ast.parse(src, path)
    except (SyntaxError, ValueError):
        return []
    offs = _line_offsets(src)
    out: list[Mutant] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        end = node.end_lineno or node.lineno
        if not any(node.lineno <= ln <= end for ln in lines):
            continue
        body = node.body
        first = body[1] if len(body) > 1 and _is_docstring(body[0]) else body[0]
        if _is_docstring(first) or first.lineno == node.lineno:
            continue  # one-line body: covered by the module-level control
        insert_at = offs[first.lineno - 1]
        indent = b" " * first.col_offset
        new = src[:insert_at] + indent + f"{CONTROL_NAME} = None\n".encode() + src[insert_at:]
        try:
            compile(new, path, "exec", dont_inherit=True)
        except (SyntaxError, ValueError):
            continue
        out.append(Mutant(f"control:{node.name}", path, first.lineno, "control", "", "", new))
    return out


def _is_docstring(stmt: ast.stmt) -> bool:
    return (
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Constant)
        and isinstance(stmt.value.value, str)
    )


def control_mutants(path: str, src: bytes, lines: set[int]) -> list[Mutant]:
    """Behaviour-preserving variants that MUST survive.

    One appends a dead module-level assignment (changes text, AST and module
    bytecode); one per changed function inserts a dead local assignment (changes
    that function's code object). If the tests "kill" any of them, they depend on
    the source text, AST or bytecode (self-hash pins), and kill counts mean nothing.
    """
    return [
        Mutant("control:module", path, 0, "control", "", "", src + CONTROL_SUFFIX),
        *_function_controls(path, src, lines),
    ]
