"""Assertion extraction and strength scoring for Python tests.

Strength is an ordinal, not a proof:

    0  vacuous     cannot fail (``assert True``, ``assert x or True``, ``x == x``)
    1  weak        truthiness, ``!=``, ``is not`` (``status != 500`` admits 401, 200, 302...)
    2  bounded     ordering, membership, isinstance, regex
    3  exact       ``==``, ``is``, exact-equality helpers, expected exceptions

Replacing an assertion on the same subject with a lower-strength one is
reported as weakening.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from aicrg.analysis.pyast import call_name, last_segment, unparse

_EXACT_METHODS = {
    "assertEqual",
    "assertEquals",
    "assertIs",
    "assertIsNone",
    "assertDictEqual",
    "assertListEqual",
    "assertTupleEqual",
    "assertSetEqual",
    "assertSequenceEqual",
    "assertCountEqual",
    "assertMultiLineEqual",
    "assertAlmostEqual",
    "assertRaises",
    "assertRaisesRegex",
    "assertWarns",
    "assertLogs",
    "assert_called_once_with",
    "assert_called_with",
    "assert_any_call",
    "assert_has_calls",
    "assert_not_called",
    "assert_awaited_once_with",
    "assert_frame_equal",
    "assert_series_equal",
    "assert_array_equal",
    "assert_allclose",
}
_BOUNDED_METHODS = {
    "assertIn",
    "assertNotIn",
    "assertGreater",
    "assertGreaterEqual",
    "assertLess",
    "assertLessEqual",
    "assertIsInstance",
    "assertRegex",
    "assertNotRegex",
    "assertNotIsInstance",
    "assert_called_once",
    "assert_called",
    "assert_awaited",
}
_WEAK_METHODS = {
    "assertTrue",
    "assertFalse",
    "assertNotEqual",
    "assertNotEquals",
    "assertIsNotNone",
    "assertIsNot",
    "assertNotAlmostEqual",
}

BROAD_EXCEPTIONS = {"Exception", "BaseException", "object"}


@dataclass(frozen=True, slots=True)
class Assertion:
    key: str  # normalised text; identity for multiset comparison
    subject: str
    strength: int
    kind: str  # "assert" | "method" | "raises"
    line: int
    expected: str | None = None  # literal on the expected side, if any
    raises: tuple[str, ...] = ()
    has_match: bool = False


def _is_truthy_constant(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and bool(node.value)


def expr_strength(test: ast.expr) -> tuple[int, str, str | None]:
    """Return (strength, subject, expected-literal) for an ``assert`` expression."""
    if isinstance(test, ast.Constant):
        return (0 if test.value else 3), unparse(test), None
    if isinstance(test, ast.BoolOp):
        if isinstance(test.op, ast.Or):
            if any(_is_truthy_constant(v) for v in test.values):
                return 0, unparse(test.values[0]), None
            # ``a or b`` passes if either holds: no stronger than its weakest arm
            parts = [expr_strength(v) for v in test.values]
            return min(*(p[0] for p in parts), 1), parts[0][1], None
        parts = [expr_strength(v) for v in test.values]
        return max(parts, key=lambda p: p[0])
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        inner = test.operand
        if isinstance(inner, ast.Constant):
            return (0 if not inner.value else 3), unparse(inner), None
        return 1, unparse(inner), None
    if isinstance(test, ast.Compare) and len(test.ops) == 1:
        left, op, right = test.left, test.ops[0], test.comparators[0]
        if unparse(left) == unparse(right):
            vacuous = isinstance(op, (ast.Eq, ast.Is, ast.LtE, ast.GtE))
            return (0 if vacuous else 3), unparse(left), None
        if isinstance(left, ast.Constant) and isinstance(right, ast.Constant):
            return 0, unparse(left), None
        # Put the non-literal side as subject.
        subject, expected = left, right
        if isinstance(left, ast.Constant) and not isinstance(right, ast.Constant):
            subject, expected = right, left
        exp_text = unparse(expected) if isinstance(expected, ast.Constant) else None
        if isinstance(op, (ast.Eq, ast.Is)):
            # ``x is not None``-style checks are weak; ``x is None`` is exact.
            return 3, unparse(subject), exp_text
        if isinstance(op, (ast.NotEq, ast.IsNot)):
            return 1, unparse(subject), exp_text
        return 2, unparse(subject), exp_text
    if isinstance(test, ast.Compare):
        return 2, unparse(test.left), None
    if isinstance(test, ast.Call):
        name = last_segment(call_name(test))
        if name in ("isinstance", "issubclass") and test.args:
            return 2, unparse(test.args[0]), None
        if name in ("all", "any") and test.args:
            inner = test.args[0]
            if isinstance(inner, (ast.GeneratorExp, ast.ListComp)):
                s, _, _ = expr_strength(inner.elt)
                return min(s, 2), unparse(inner.elt), None
        return 1, unparse(test), None
    return 1, unparse(test), None


def _method_assertion(call: ast.Call) -> Assertion | None:
    name = last_segment(call_name(call))
    if not (name.startswith("assert") or name.startswith("assert_")):
        return None
    if name in _EXACT_METHODS:
        strength = 3
    elif name in _BOUNDED_METHODS:
        strength = 2
    elif name in _WEAK_METHODS:
        strength = 1
    else:
        strength = 2
    # assertTrue(True) / assertEqual(x, x) are vacuous
    if call.args:
        if name == "assertTrue" and _is_truthy_constant(call.args[0]):
            strength = 0
        if (
            name == "assertFalse"
            and isinstance(call.args[0], ast.Constant)
            and not call.args[0].value
        ):
            strength = 0
        if len(call.args) >= 2 and unparse(call.args[0]) == unparse(call.args[1]):
            strength = 0
    subject = unparse(call.args[0]) if call.args else name
    expected = None
    if len(call.args) >= 2 and isinstance(call.args[1], ast.Constant):
        expected = unparse(call.args[1])
    if name in ("assertRaises", "assertRaisesRegex") and call.args:
        excs = _exc_names(call.args[0])
        return Assertion(
            key="raises:" + ",".join(excs) + (":match" if name.endswith("Regex") else ""),
            subject="raises",
            strength=3,
            kind="raises",
            line=call.lineno,
            raises=excs,
            has_match=name.endswith("Regex"),
        )
    return Assertion(unparse(call), subject, strength, "method", call.lineno, expected)


def _exc_names(node: ast.AST) -> tuple[str, ...]:
    if isinstance(node, ast.Tuple):
        return tuple(sorted(unparse(e) for e in node.elts))
    return (unparse(node),)


def _raises_assertion(call: ast.Call) -> Assertion | None:
    name = call_name(call)
    if last_segment(name) not in ("raises", "assertRaises", "assertRaisesRegex"):
        return None
    if last_segment(name) == "raises" and not name.endswith("pytest.raises") and name != "raises":
        return None
    if not call.args:
        return None
    excs = _exc_names(call.args[0])
    has_match = any(k.arg == "match" for k in call.keywords) or name.endswith("Regex")
    return Assertion(
        key="raises:" + ",".join(excs) + (":match" if has_match else ""),
        subject="raises",
        strength=3,
        kind="raises",
        line=call.lineno,
        raises=excs,
        has_match=has_match,
    )


def extract_assertions(func: ast.AST) -> list[Assertion]:
    out: list[Assertion] = []
    for node in ast.walk(func):
        if isinstance(node, ast.Assert):
            strength, subject, expected = expr_strength(node.test)
            out.append(
                Assertion(
                    "assert " + unparse(node.test),
                    subject,
                    strength,
                    "assert",
                    node.lineno,
                    expected,
                )
            )
        elif isinstance(node, ast.Call):
            r = _raises_assertion(node)
            if r is not None:
                out.append(r)
                continue
            m = _method_assertion(node)
            if m is not None:
                out.append(m)
    out.sort(key=lambda a: (a.line, a.key))
    return out


def exception_broadened(before: Assertion, after: Assertion) -> bool:
    if before.kind != "raises" or after.kind != "raises":
        return False
    b, a = set(before.raises), set(after.raises)
    if (a & BROAD_EXCEPTIONS) and not (b & BROAD_EXCEPTIONS):
        return True
    if b < a:  # tuple grew: more exception types accepted
        return True
    return bool(before.has_match and not after.has_match and a == b)
