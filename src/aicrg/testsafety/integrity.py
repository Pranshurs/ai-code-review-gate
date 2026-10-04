"""Diff-aware test-integrity analysis (Python, AST based).

The question is not "are the tests good?" but "did this patch make the tests
prove less than they did at base?". Every signal compares base and head.

Limits (documented in docs/TEST_INTEGRITY.md): helpers that assert indirectly,
fixtures that change behaviour, and semantic weakening that keeps the same
syntactic shape are not detected. Uncertain cases surface as REVIEW_REQUIRED.
"""

from __future__ import annotations

import ast
import re
from collections import Counter
from dataclasses import dataclass, field

from aicrg.analysis.context import PatchContext, is_python, is_test_path
from aicrg.analysis.pyast import call_name, dotted, last_segment, unparse
from aicrg.globmatch import match_any
from aicrg.model import Finding, Severity
from aicrg.rules import finding
from aicrg.testsafety.assertions import Assertion, exception_broadened, extract_assertions

SECURITY_TEST_RE = re.compile(
    r"(auth|login|logout|permission|forbidden|unauthori[sz]ed|admin|csrf|xss|inject|secur|"
    r"token|secret|password|passwd|tls|ssl|cert|verify|signature|role|access|privilege|"
    r"sanitiz|escape|traversal|deny|denied|reject|401|403|scope|tenant|rbac|acl|session)",
    re.I,
)

COLLECTION_HOOKS = {
    "pytest_collection_modifyitems",
    "pytest_ignore_collect",
    "pytest_collect_file",
    "pytest_runtest_setup",
    "pytest_runtest_call",
    "pytest_runtest_makereport",
    "pytest_configure",
    "collect_ignore",
    "collect_ignore_glob",
    "pytestmark",
}


@dataclass(slots=True)
class TestCase:
    file: str
    qualname: str
    node: ast.FunctionDef | ast.AsyncFunctionDef
    assertions: list[Assertion]
    markers: list[tuple[str, str]]  # (classification, text)
    security: bool

    @property
    def assertion_keys(self) -> Counter[str]:
        return Counter(a.key for a in self.assertions)


@dataclass(slots=True)
class TestIntegrityReport:
    findings: list[Finding] = field(default_factory=list)
    tests_before: int = 0
    tests_after: int = 0
    assertions_before: int = 0
    assertions_after: int = 0
    files_analysed: int = 0

    def to_json(self) -> dict[str, object]:
        return {
            "tests_before": self.tests_before,
            "tests_after": self.tests_after,
            "assertions_before": self.assertions_before,
            "assertions_after": self.assertions_after,
            "files_analysed": self.files_analysed,
        }


# --------------------------------------------------------------------------- markers


def _classify_marker(dec: ast.expr) -> tuple[str, str] | None:
    """Return (classification, text) for skip/xfail decorators."""
    target = dec.func if isinstance(dec, ast.Call) else dec
    name = dotted(target)
    seg = last_segment(name)
    text = unparse(dec)
    args = dec.args if isinstance(dec, ast.Call) else []
    kws = {k.arg: k.value for k in dec.keywords} if isinstance(dec, ast.Call) else {}
    if seg == "skip" and ("mark" in name or "unittest" in name or name == "skip"):
        return "unconditional_skip", text
    if seg in ("skipif", "skipIf"):
        cond = args[0] if args else kws.get("condition")
        if isinstance(cond, ast.Constant) and bool(cond.value) and not isinstance(cond.value, str):
            return "unconditional_skip", text
        return "conditional_skip", text
    if seg == "skipUnless":
        cond = args[0] if args else None
        if isinstance(cond, ast.Constant) and not cond.value:
            return "unconditional_skip", text
        return "conditional_skip", text
    if seg in {"xfail", "expectedFailure"}:
        return "xfail", text
    return None


def _body_skip_calls(func: ast.AST) -> list[tuple[str, str]]:
    """``pytest.skip()``/``self.skipTest()`` in the test body."""
    out: list[tuple[str, str]] = []
    body = getattr(func, "body", [])
    for stmt in body:
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            seg = last_segment(call_name(stmt.value))
            if seg in ("skip", "skipTest"):
                out.append(("unconditional_skip", unparse(stmt.value)))
            elif seg == "xfail":
                out.append(("xfail", unparse(stmt.value)))
    for node in ast.walk(func):
        if isinstance(node, ast.If):
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call) and last_segment(call_name(sub)) in (
                    "skip",
                    "skipTest",
                ):
                    out.append(("conditional_skip", unparse(sub)))
    return out


def _module_markers(module: ast.Module) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for stmt in module.body:
        if isinstance(stmt, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "pytestmark" for t in stmt.targets
        ):
            vals = (
                stmt.value.elts if isinstance(stmt.value, (ast.List, ast.Tuple)) else [stmt.value]
            )
            for v in vals:
                m = _classify_marker(v)
                if m:
                    out.append(m)
        # module-level pytest.skip(allow_module_level=True)
        if (
            isinstance(stmt, ast.Expr)
            and isinstance(stmt.value, ast.Call)
            and last_segment(call_name(stmt.value)) == "skip"
        ):
            out.append(("unconditional_skip", unparse(stmt.value)))
    return out


# --------------------------------------------------------------------------- collection


def _collect_tests(path: str, module: ast.Module) -> dict[str, TestCase]:
    tests: dict[str, TestCase] = {}
    module_markers = _module_markers(module)

    def visit(body: list[ast.stmt], prefix: str, inherited: list[tuple[str, str]]) -> None:
        for stmt in body:
            if isinstance(stmt, ast.ClassDef):
                cls_markers = [m for d in stmt.decorator_list if (m := _classify_marker(d))]
                visit(stmt.body, f"{prefix}{stmt.name}.", inherited + cls_markers)
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and stmt.name.startswith(
                "test"
            ):
                q = prefix + stmt.name
                markers = (
                    inherited
                    + [m for d in stmt.decorator_list if (m := _classify_marker(d))]
                    + _body_skip_calls(stmt)
                )
                assertions = extract_assertions(stmt)
                hay = " ".join([path, q, *(a.key for a in assertions)])
                tests[q] = TestCase(
                    path, q, stmt, assertions, markers, bool(SECURITY_TEST_RE.search(hay))
                )

    visit(module.body, "", module_markers)
    return tests


def _parametrize_counts(func: ast.AST) -> dict[str, tuple[int, list[str]]]:
    out: dict[str, tuple[int, list[str]]] = {}
    for dec in getattr(func, "decorator_list", []):
        if not isinstance(dec, ast.Call) or last_segment(call_name(dec)) != "parametrize":
            continue
        if len(dec.args) < 2:
            continue
        names = unparse(dec.args[0])
        values = dec.args[1]
        if isinstance(values, (ast.List, ast.Tuple)):
            out[names] = (len(values.elts), [unparse(e) for e in values.elts])
    return out


def _unreachable_after_return(func: ast.AST) -> bool:
    body = getattr(func, "body", [])
    for i, stmt in enumerate(body):
        if isinstance(stmt, ast.Return):
            rest = body[i + 1 :]
            return any(
                isinstance(n, ast.Assert)
                or (isinstance(n, ast.Call) and last_segment(call_name(n)).startswith("assert"))
                for r in rest
                for n in ast.walk(r)
            )
    return False


def _swallowed_assertion_blocks(func: ast.AST) -> int:
    count = 0
    for node in ast.walk(func):
        if not isinstance(node, ast.Try):
            continue
        has_assert = any(
            isinstance(n, ast.Assert)
            or (isinstance(n, ast.Call) and last_segment(call_name(n)).startswith("assert"))
            for s in node.body
            for n in ast.walk(s)
        )
        if not has_assert:
            continue
        for h in node.handlers:
            tname = unparse(h.type) if h.type is not None else ""
            broad = tname in ("", "Exception", "BaseException", "AssertionError") or (
                "AssertionError" in tname
            )
            reraises = any(isinstance(n, ast.Raise) for s in h.body for n in ast.walk(s))
            fails = any(
                isinstance(n, ast.Call) and last_segment(call_name(n)) in ("fail", "fail_test")
                for s in h.body
                for n in ast.walk(s)
            )
            if broad and not reraises and not fails:
                count += 1
    return count


# --------------------------------------------------------------------------- analysis


class _Analyzer:
    def __init__(self, ctx: PatchContext) -> None:
        self.ctx = ctx
        self.contract = ctx.contract
        self.ti = ctx.contract.minimum_test_integrity
        self.report = TestIntegrityReport()
        self.removed: list[tuple[TestCase, bool]] = []  # (test, file_deleted)
        self.added: list[TestCase] = []

    # severity helpers -----------------------------------------------------------
    def _weakening_severity(self, security: bool) -> Severity:
        if self.ti.forbid_assertion_weakening:
            return Severity.BLOCK
        if security and self.ti.forbid_removed_security_assertions:
            return Severity.BLOCK
        return Severity.REVIEW

    def _removal_severity(self, security: bool) -> Severity:
        if security and self.ti.forbid_removed_security_assertions:
            return Severity.BLOCK
        return Severity.REVIEW

    def add(self, f: Finding) -> None:
        self.report.findings.append(f)

    # ---------------------------------------------------------------------------
    def run(self) -> TestIntegrityReport:
        for fc in self.ctx.patch.files:
            for p in fc.paths:
                pat = match_any(p, self.contract.golden_paths)
                if pat and fc.status != "A":
                    self.add(
                        finding(
                            "golden_data_modified",
                            self.contract,
                            f"golden/expected data {fc.status_word()} ({pat}); "
                            "expected outputs changed rather than implementation",
                            file=p,
                        )
                    )
                    break
            old_test = (
                fc.old_path is not None and is_test_path(fc.old_path) and is_python(fc.old_path)
            )
            new_test = (
                fc.new_path is not None and is_test_path(fc.new_path) and is_python(fc.new_path)
            )
            if not (old_test or new_test):
                continue
            self.report.files_analysed += 1
            base_mod = self.ctx.base_ast(fc) if old_test else None
            head_mod = self.ctx.head_ast(fc) if new_test else None
            if new_test and head_mod is None and self.ctx.head_bytes(fc) is not None:
                self.add(
                    finding(
                        "unparseable_python",
                        self.contract,
                        "test file does not parse at head; test-integrity analysis skipped",
                        file=fc.new_path,
                    )
                )
                continue
            before = _collect_tests(fc.old_path, base_mod) if base_mod and fc.old_path else {}
            after = _collect_tests(fc.new_path, head_mod) if head_mod and fc.new_path else {}
            self.report.tests_before += len(before)
            self.report.tests_after += len(after)
            self.report.assertions_before += sum(len(t.assertions) for t in before.values())
            self.report.assertions_after += sum(len(t.assertions) for t in after.values())
            file_deleted = fc.status == "D" or not new_test
            for q, t in before.items():
                if q not in after:
                    self.removed.append((t, file_deleted))
            for q, t in after.items():
                if q not in before:
                    self.added.append(t)
                    self._new_test(t)
                else:
                    self._compare(before[q], t)
            if base_mod is not None and head_mod is not None:
                self._collection_hooks(fc.path, base_mod, head_mod)
        self._resolve_removals()
        self.report.findings.sort(key=Finding.sort_key)
        return self.report

    def _new_test(self, t: TestCase) -> None:
        for a in t.assertions:
            if a.strength == 0:
                self.add(
                    finding(
                        "vacuous_assertion_added",
                        self.contract,
                        f"new test {t.qualname} asserts something that cannot fail",
                        file=t.file,
                        line=a.line,
                        after=a.key,
                        severity=self._weakening_severity(t.security),
                    )
                )
        self._markers([], t)

    def _markers(self, before: list[tuple[str, str]], t: TestCase) -> None:
        old = Counter(before)
        for cls, text in t.markers:
            if old[(cls, text)] > 0:
                old[(cls, text)] -= 1
                continue
            if cls == "unconditional_skip":
                sev = Severity.BLOCK if self.ti.forbid_new_unconditional_skips else Severity.REVIEW
                self.add(
                    finding(
                        "unconditional_skip_added",
                        self.contract,
                        f"{t.qualname} is now skipped unconditionally",
                        file=t.file,
                        line=t.node.lineno,
                        after=text,
                        severity=sev,
                    )
                )
            elif cls == "xfail":
                self.add(
                    finding(
                        "xfail_added",
                        self.contract,
                        f"{t.qualname} now marked as expected failure"
                        + ("" if "reason" in text else " without a reason"),
                        file=t.file,
                        line=t.node.lineno,
                        after=text,
                    )
                )
            elif cls == "conditional_skip":
                self.add(
                    finding(
                        "conditional_skip_added",
                        self.contract,
                        f"{t.qualname} gained a conditional skip",
                        file=t.file,
                        line=t.node.lineno,
                        after=text,
                    )
                )

    def _compare(self, b: TestCase, h: TestCase) -> None:
        security = b.security or h.security
        self._markers(b.markers, h)
        # control-flow tricks
        if _unreachable_after_return(h.node) and not _unreachable_after_return(b.node):
            self.add(
                finding(
                    "unreachable_assertions",
                    self.contract,
                    f"{h.qualname} returns before its assertions run",
                    file=h.file,
                    line=h.node.lineno,
                    severity=self._weakening_severity(security),
                )
            )
        if _swallowed_assertion_blocks(h.node) > _swallowed_assertion_blocks(b.node):
            self.add(
                finding(
                    "assertion_swallowed",
                    self.contract,
                    f"{h.qualname} wraps assertions in a handler that hides failures",
                    file=h.file,
                    line=h.node.lineno,
                    severity=self._weakening_severity(security),
                )
            )
        # parametrize
        pb, ph = _parametrize_counts(b.node), _parametrize_counts(h.node)
        for names, (n_before, cases_before) in pb.items():
            n_after, cases_after = ph.get(names, (0, []))
            if names in ph and n_after < n_before:
                gone = [c for c in cases_before if c not in cases_after]
                self.add(
                    finding(
                        "parametrize_cases_reduced",
                        self.contract,
                        f"{h.qualname}: parametrized cases {n_before} -> {n_after}",
                        file=h.file,
                        line=h.node.lineno,
                        before="; ".join(gone[:5]),
                        severity=self._removal_severity(security),
                    )
                )
        # assertions as multisets
        kb, kh = b.assertion_keys, h.assertion_keys
        removed_keys = kb - kh
        added_keys = kh - kb
        removed = _take(b.assertions, removed_keys)
        added = _take(h.assertions, added_keys)
        unmatched_added = list(added)
        unmatched_removed: list[Assertion] = []
        for r in removed:
            partner = next((a for a in unmatched_added if a.subject == r.subject), None)
            if partner is None:
                unmatched_removed.append(r)
                continue
            unmatched_added.remove(partner)
            self._pair(h, r, partner, security)
        # pair leftovers positionally (subject rewritten as well)
        leftovers = list(zip(unmatched_removed, unmatched_added, strict=False))
        for r, a in leftovers:
            if a.strength < r.strength or exception_broadened(r, a):
                self._pair(h, r, a, security)
        net_removed = unmatched_removed[len(leftovers) :]
        for a in unmatched_added[len(leftovers) :]:
            if a.strength == 0:
                self.add(
                    finding(
                        "vacuous_assertion_added",
                        self.contract,
                        f"{h.qualname} gained an assertion that cannot fail",
                        file=h.file,
                        line=a.line,
                        after=a.key,
                        severity=self._weakening_severity(security),
                    )
                )
        if net_removed:
            self.add(
                finding(
                    "assertion_removed",
                    self.contract,
                    f"{h.qualname}: {len(net_removed)} assertion(s) removed"
                    + (" from a security-relevant test" if security else ""),
                    file=h.file,
                    line=h.node.lineno,
                    before="\n".join(r.key for r in net_removed[:5]),
                    severity=self._removal_severity(security),
                )
            )

    def _pair(self, h: TestCase, r: Assertion, a: Assertion, security: bool) -> None:
        sev = self._weakening_severity(security)
        if r.kind == "raises" or a.kind == "raises":
            if exception_broadened(r, a):
                self.add(
                    finding(
                        "expected_exception_broadened",
                        self.contract,
                        f"{h.qualname}: expected exception broadened",
                        file=h.file,
                        line=a.line,
                        before=r.key,
                        after=a.key,
                        severity=sev,
                    )
                )
            return
        if a.strength < r.strength:
            code = "vacuous_assertion_added" if a.strength == 0 else "assertion_weakened"
            self.add(
                finding(
                    code,
                    self.contract,
                    f"{h.qualname}: assertion on `{r.subject}` weakened "
                    f"(strength {r.strength} -> {a.strength})",
                    file=h.file,
                    line=a.line,
                    before=r.key,
                    after=a.key,
                    severity=sev,
                )
            )
        elif (
            a.strength == r.strength
            and r.expected is not None
            and a.expected is not None
            and r.expected != a.expected
        ):
            self.add(
                finding(
                    "expected_value_changed",
                    self.contract,
                    f"{h.qualname}: expected value for `{r.subject}` changed "
                    f"{r.expected} -> {a.expected}",
                    file=h.file,
                    line=a.line,
                    before=r.key,
                    after=a.key,
                )
            )

    def _resolve_removals(self) -> None:
        pool = list(self.added)
        deleted_files: dict[str, list[TestCase]] = {}
        for t, file_deleted in self.removed:
            twin = next(
                (
                    n
                    for n in pool
                    if t.assertions
                    and n.assertion_keys == t.assertion_keys
                    and n.markers == t.markers
                ),
                None,
            )
            if twin is not None:
                pool.remove(twin)
                self.add(
                    finding(
                        "test_function_renamed",
                        self.contract,
                        f"{t.file}::{t.qualname} moved/renamed to "
                        f"{twin.file}::{twin.qualname} with identical assertions",
                        file=twin.file,
                        line=twin.node.lineno,
                    )
                )
                continue
            if file_deleted:
                deleted_files.setdefault(t.file, []).append(t)
            else:
                self.add(
                    finding(
                        "test_function_removed",
                        self.contract,
                        f"test {t.qualname} removed"
                        + (" (security-relevant)" if t.security else ""),
                        file=t.file,
                        line=t.node.lineno,
                        before=f"{len(t.assertions)} assertion(s)",
                    )
                )
        for path, tests in sorted(deleted_files.items()):
            sec = [t.qualname for t in tests if t.security]
            self.add(
                finding(
                    "test_file_deleted",
                    self.contract,
                    f"test file removed with {len(tests)} test(s)"
                    + (f"; security-relevant: {', '.join(sec[:5])}" if sec else ""),
                    file=path,
                )
            )

    def _collection_hooks(self, path: str, base: ast.Module, head: ast.Module) -> None:
        if not path.endswith("conftest.py") and "pytestmark" not in unparse(head):
            return

        def hooks(mod: ast.Module) -> dict[str, str]:
            out: dict[str, str] = {}
            for stmt in mod.body:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
                    stmt.name in COLLECTION_HOOKS
                ):
                    out[stmt.name] = ast.dump(stmt)
                elif isinstance(stmt, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                    targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                    for tgt in targets:
                        if isinstance(tgt, ast.Name) and tgt.id in COLLECTION_HOOKS:
                            out[tgt.id] = out.get(tgt.id, "") + ast.dump(stmt)
            return out

        hb, hh = hooks(base), hooks(head)
        for name in sorted(set(hb) | set(hh)):
            if hb.get(name) != hh.get(name) and name != "pytestmark":
                self.add(
                    finding(
                        "collection_hook_modified",
                        self.contract,
                        f"pytest collection hook `{name}` changed; it can skip or "
                        "deselect tests globally",
                        file=path,
                    )
                )


def _take(items: list[Assertion], wanted: Counter[str]) -> list[Assertion]:
    left = Counter(wanted)
    out: list[Assertion] = []
    for a in items:
        if left[a.key] > 0:
            left[a.key] -= 1
            out.append(a)
    return out


def analyze_test_integrity(ctx: PatchContext) -> TestIntegrityReport:
    return _Analyzer(ctx).run()
