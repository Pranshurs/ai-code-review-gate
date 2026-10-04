"""Diff-aware detection of patches that weaken defensive code (Python).

Two shapes of signal:

* **Defensive facts removed**: per function, compared base vs head by
  qualified name (auth checks, denial sites, auth decorators, validation,
  constant-time comparison, path containment). A decrease is reported.
* **Dangerous constructs introduced**: multiset of (function, construct) at
  base vs head; only occurrences that did not exist before are reported, so
  moving existing code is not flagged.

Pre-existing problems are never reported: this is a regression gate, not a
scanner. Run Bandit/Semgrep/CodeQL as required checks for absolute findings.
"""

from __future__ import annotations

import ast
import re
from collections import Counter
from dataclasses import dataclass, field

from aicrg.analysis.context import PatchContext, is_test_path
from aicrg.analysis.pyast import (
    FuncNode,
    call_name,
    dotted,
    is_dynamic_string,
    iter_functions,
    last_segment,
    unparse,
)
from aicrg.model import Finding
from aicrg.rules import finding

DENY_EXC_RE = re.compile(
    r"(Unauthori[sz]ed|Forbidden|PermissionDenied|PermissionError|Auth\w*Error|"
    r"AuthenticationFailed|NotAuthenticated|AccessDenied|AuthorizationError|Http40[13]|"
    r"NotAuthorized|InvalidToken|InvalidSignature)"
)
AUTH_CALL_RE = re.compile(
    r"^((check|require|ensure|verify|assert|enforce|validate)_?\w*"
    r"(auth|perm|role|admin|login|access|owner|scope|privilege|token|session|csrf|signature)\w*|"
    r"is_authenticated|is_authorized|has_perms?|has_permission|has_role|has_scope|is_admin|"
    r"is_staff|is_superuser|is_owner|authorize\w*|authenticate\w*|can_\w+|permission_required|"
    r"login_required|verify_password|check_password|decode_token|verify_jwt\w*)$",
    re.I,
)
AUTH_ATTR_RE = re.compile(
    r"^(is_admin|is_authenticated|is_staff|is_superuser|is_active|role|roles|permissions|"
    r"scopes|is_owner|owner_id|user_id|tenant_id|is_anonymous|authenticated)$"
)
AUTH_DECO_RE = re.compile(
    r"^(login_required|permission_required|requires?_\w+|auth\w*|roles?_required|admin_required|"
    r"protected|secured|jwt_required|user_passes_test|staff_member_required|csrf_protect|"
    r"authorize\w*|authenticated|permission_classes|has_role|require_role|fresh_login_required)$",
    re.I,
)
EXEMPT_DECO_RE = re.compile(
    r"^(csrf_exempt|allow_any|AllowAny|public|no_auth|skip_auth\w*|unauthenticated|"
    r"permission_classes_none|exempt\w*)$"
)
VALIDATION_CALL_RE = re.compile(
    r"^(validate\w*|_validate\w*|sanitiz\w*|clean_\w+|is_valid\w*|check_\w*(input|format|length|"
    r"range|size|type|bounds|schema|name|path|url)\w*|escape|quote|fullmatch|ensure_\w+)$",
    re.I,
)
VALIDATION_EXC_RE = re.compile(
    r"(ValueError|ValidationError|TypeError|BadRequest|Invalid\w*|"
    r"SchemaError|UnprocessableEntity)"
)
PATH_GUARD_RE = re.compile(r"^(is_relative_to|commonpath|secure_filename|safe_join|realpath)$")
TLS_KW = {
    "verify",
    "verify_ssl",
    "ssl_verify",
    "verify_certs",
    "check_hostname",
    "ssl",
    "verify_tls",
    "tls_verify",
    "cert_reqs",
}
SEC_FLAG_RE = re.compile(
    r"(verif|validat|secur|auth|csrf|ssl|tls|enforce|sanitiz|escap|protect|"
    r"signature|https|httponly|xss|permission|encrypt)",
    re.I,
)
INSECURE_FLAG_RE = re.compile(
    r"^(insecure\w*|\w*disable_?\w*(auth|verif|ssl|tls|csrf|secur|valid|check)\w*|"
    r"skip_?\w*(auth|verif|valid|check)\w*|allow_?\w*(insecure|unsafe|anonymous|all|any)\w*|"
    r"unsafe\w*|bypass\w*)$",
    re.I,
)
SHELL_FUNCS = {
    "os.system",
    "os.popen",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",
    "commands.getoutput",
    "asyncio.create_subprocess_shell",
    "os.popen2",
    "os.popen3",
}
SUBPROCESS_FUNCS = {
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
    "run",
    "Popen",
    "check_output",
    "check_call",
    "call",
}
DESER_RE = re.compile(
    r"^(c?pickle|dill|marshal|cloudpickle|jsonpickle|shelve)\.(loads?|open|decode|"
    r"Unpickler)$|^yaml\.(unsafe_load|unsafe_load_all|full_load)$"
)
WEAK_HASH = {"hashlib.md5", "hashlib.sha1", "md5", "sha1"}


@dataclass(slots=True)
class FuncFacts:
    auth: Counter[str] = field(default_factory=Counter)
    auth_decos: Counter[str] = field(default_factory=Counter)
    exempt_decos: Counter[str] = field(default_factory=Counter)
    validation: Counter[str] = field(default_factory=Counter)
    compare_digest: int = 0
    path_guards: Counter[str] = field(default_factory=Counter)


def _is_deny_status(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value in (401, 403)


def _func_facts(func: ast.FunctionDef | ast.AsyncFunctionDef) -> FuncFacts:
    f = FuncFacts()
    for d in func.decorator_list:
        name = last_segment(dotted(d.func if isinstance(d, ast.Call) else d))
        if AUTH_DECO_RE.match(name):
            f.auth_decos[unparse(d)] += 1
        if EXEMPT_DECO_RE.match(name):
            f.exempt_decos[unparse(d)] += 1
    for node in _walk_own(func):
        if isinstance(node, ast.Raise) and node.exc is not None:
            exc = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
            ename = last_segment(dotted(exc))
            if DENY_EXC_RE.search(ename) or (
                isinstance(node.exc, ast.Call)
                and any(
                    _is_deny_status(a)
                    for a in [*node.exc.args, *(k.value for k in node.exc.keywords)]
                )
            ):
                f.auth["raise " + ename] += 1
            elif VALIDATION_EXC_RE.search(ename):
                f.validation["raise " + ename] += 1
        elif isinstance(node, ast.Call):
            name = call_name(node)
            seg = last_segment(name)
            if seg == "compare_digest":
                f.compare_digest += 1
            if AUTH_CALL_RE.match(seg):
                f.auth[seg] += 1
            elif VALIDATION_CALL_RE.match(seg):
                f.validation[seg] += 1
            if PATH_GUARD_RE.match(seg):
                f.path_guards[seg] += 1
            if seg in (
                "abort",
                "HTTPException",
                "Response",
                "JSONResponse",
                "HttpResponse",
                "make_response",
                "jsonify",
            ) and any(_is_deny_status(a) for a in [*node.args, *(k.value for k in node.keywords)]):
                f.auth[f"{seg}(40x)"] += 1
        elif isinstance(node, ast.Return) and isinstance(node.value, ast.Tuple):
            if any(_is_deny_status(e) for e in node.value.elts):
                f.auth["return 40x"] += 1
        elif isinstance(node, (ast.If, ast.Assert, ast.IfExp, ast.While)):
            for sub in ast.walk(node.test):
                if isinstance(sub, ast.Attribute) and AUTH_ATTR_RE.match(sub.attr):
                    f.auth["test ." + sub.attr] += 1
                if isinstance(sub, ast.Compare) and any(
                    _is_deny_status(c) for c in sub.comparators
                ):
                    f.auth["test 40x"] += 1
    return f


def _helper_auth(func: ast.AST, funcs: dict[str, FuncNode]) -> Counter[str]:
    """Auth facts of same-module functions called directly from ``func``.

    Extracting a check into a helper ("_require_owner(doc)") is a refactor, not a
    removal. Only direct calls to module-level functions are followed (one level).
    """
    out: Counter[str] = Counter()
    for node in _walk_own(func):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            target = funcs.get(node.func.id)
            if target is not None and target is not func:
                out += _func_facts(target).auth
    return out


def _walk_own(func: ast.AST) -> list[ast.AST]:
    """Walk a function body without descending into nested defs/classes."""
    out: list[ast.AST] = []
    stack: list[ast.AST] = list(getattr(func, "body", []))
    while stack:
        node = stack.pop()
        out.append(node)
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue
            stack.append(child)
    return out


# --------------------------------------------------------------------------- dangerous constructs


@dataclass(frozen=True, slots=True)
class Signal:
    code: str
    scope: str
    text: str
    line: int
    detail: str


def _is_placeholder_value(node: ast.expr) -> bool:
    """A literal that stands in for a real result: None, False, 0, "", {}, [], ()."""
    if isinstance(node, ast.Constant):
        return node.value is not True  # ``return True`` is reported as fail-open instead
    if isinstance(node, (ast.Dict, ast.List, ast.Tuple, ast.Set)):
        return all(
            isinstance(e, ast.Constant)
            for e in (node.values if isinstance(node, ast.Dict) else node.elts)
        )
    return False


def _handler_swallows(h: ast.ExceptHandler) -> bool:
    body = [
        s
        for s in h.body
        if not (
            isinstance(s, ast.Expr)
            and isinstance(s.value, ast.Constant)
            and isinstance(s.value.value, str)
        )
    ]
    if not body:
        return True
    return all(
        isinstance(s, (ast.Pass, ast.Continue, ast.Break))
        or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))
        or (isinstance(s, ast.Return) and (s.value is None or _is_placeholder_value(s.value)))
        for s in body
    )


def _is_broad(h: ast.ExceptHandler) -> bool:
    if h.type is None:
        return True
    names = h.type.elts if isinstance(h.type, ast.Tuple) else [h.type]
    return any(last_segment(dotted(n)) in ("Exception", "BaseException") for n in names)


def _signals(module: ast.Module) -> list[Signal]:
    out: list[Signal] = []
    scopes: list[tuple[str, ast.AST]] = [("<module>", module)]
    scopes += [(i.qualname, i.node) for i in iter_functions(module)]
    for scope, root in scopes:
        nodes = _walk_own(root) if root is not module else _module_level_nodes(module)
        if root is not module:
            nodes = [root, *nodes]  # the def itself carries parameter defaults
        for node in nodes:
            out.extend(_node_signals(scope, node))
    return out


def _module_level_nodes(module: ast.Module) -> list[ast.AST]:
    out: list[ast.AST] = []
    stack: list[ast.AST] = list(module.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        out.append(node)
        stack.extend(ast.iter_child_nodes(node))
    return out


def _node_signals(scope: str, node: ast.AST) -> list[Signal]:
    out: list[Signal] = []
    line = getattr(node, "lineno", 0)
    if isinstance(node, ast.ExceptHandler):
        body_text = "; ".join(unparse(s) for s in node.body)
        tname = unparse(node.type) if node.type is not None else "<bare>"
        if _is_broad(node) and _handler_swallows(node):
            out.append(
                Signal(
                    "broad_exception_swallowed",
                    scope,
                    f"except {tname}: {body_text}",
                    line,
                    f"`except {tname}` discards the error ({body_text or 'empty'})",
                )
            )
        for s in node.body:
            if (
                isinstance(s, ast.Return)
                and isinstance(s.value, ast.Constant)
                and (s.value.value is True)
            ):
                out.append(
                    Signal(
                        "fail_open_handler",
                        scope,
                        f"except {tname}: return True",
                        line,
                        f"`except {tname}` returns True (fails open)",
                    )
                )
    if isinstance(node, ast.Call):
        name = call_name(node)
        seg = last_segment(name)
        kws = {k.arg: k.value for k in node.keywords if k.arg}
        # shell execution
        shell_kw = kws.get("shell")
        uses_shell = name in SHELL_FUNCS or (
            (name in SUBPROCESS_FUNCS or name.startswith("subprocess."))
            and shell_kw is not None
            and not (isinstance(shell_kw, ast.Constant) and not shell_kw.value)
        )
        if uses_shell:
            cmd = node.args[0] if node.args else kws.get("args") or kws.get("cmd")
            dynamic = cmd is None or is_dynamic_string(cmd)
            code = "shell_injection_risk" if dynamic else "shell_execution_added"
            out.append(
                Signal(
                    code,
                    scope,
                    unparse(node),
                    line,
                    f"`{name}` runs a shell command"
                    + (" built from non-literal input" if dynamic else ""),
                )
            )
        # contextlib.suppress(Exception) is a broad except-pass in disguise
        if seg == "suppress" and any(
            last_segment(dotted(a)) in ("Exception", "BaseException") for a in node.args
        ):
            out.append(
                Signal(
                    "broad_exception_swallowed",
                    scope,
                    unparse(node),
                    line,
                    f"`{unparse(node)}` discards every error raised in its block",
                )
            )
        # deserialization / dynamic code
        if DESER_RE.match(name):
            out.append(
                Signal(
                    "unsafe_deserialization",
                    scope,
                    unparse(node),
                    line,
                    f"`{name}` can execute code from untrusted data",
                )
            )
        if name in ("yaml.load", "yaml.load_all"):
            loader = kws.get("Loader") or (node.args[1] if len(node.args) > 1 else None)
            if loader is None or "Safe" not in unparse(loader):
                out.append(
                    Signal(
                        "unsafe_deserialization",
                        scope,
                        unparse(node),
                        line,
                        f"`{name}` without SafeLoader",
                    )
                )
        if name in ("eval", "exec", "builtins.eval", "builtins.exec"):
            out.append(
                Signal(
                    "dynamic_code_execution",
                    scope,
                    unparse(node),
                    line,
                    f"`{name}()` executes dynamic code",
                )
            )
        if name in WEAK_HASH or (
            name == "hashlib.new"
            and node.args
            and unparse(node.args[0]).strip("'\"").lower() in ("md5", "sha1")
        ):
            out.append(Signal("weak_hash_added", scope, unparse(node), line, f"`{name}` is weak"))
        if seg in ("_create_unverified_context",):
            out.append(
                Signal(
                    "tls_verification_disabled",
                    scope,
                    unparse(node),
                    line,
                    "unverified SSL context",
                )
            )
        if seg == "disable_warnings" and "urllib3" in name:
            out.append(
                Signal(
                    "tls_verification_disabled",
                    scope,
                    unparse(node),
                    line,
                    "urllib3 certificate warnings silenced",
                )
            )
        for k, v in kws.items():
            out.extend(_flag_signal(scope, k, v, line, f"{seg}({k}=...)"))
        debug = kws.get("debug")
        if seg == "run" and isinstance(debug, ast.Constant) and debug.value is True:
            out.append(
                Signal("debug_mode_enabled", scope, unparse(node), line, "app run with debug")
            )
    if isinstance(node, ast.Dict):
        for key_node, val in zip(node.keys, node.values, strict=False):
            if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
                name = key_node.value
                out.extend(_flag_signal(scope, name, val, line, f"{{'{name}': ...}}"))
    if isinstance(node, (ast.Assign, ast.AnnAssign)):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        value = node.value
        for t in targets:
            tname = (
                t.id
                if isinstance(t, ast.Name)
                else (t.attr if isinstance(t, ast.Attribute) else "")
            )
            if not tname or value is None:
                continue
            if tname.upper() == "DEBUG" and isinstance(value, ast.Constant) and value.value is True:
                out.append(Signal("debug_mode_enabled", scope, unparse(node), line, "DEBUG = True"))
            if tname in ("verify_mode",) and "CERT_NONE" in unparse(value):
                out.append(
                    Signal(
                        "tls_verification_disabled",
                        scope,
                        unparse(node),
                        line,
                        "ssl verify_mode = CERT_NONE",
                    )
                )
            out.extend(_flag_signal(scope, tname, value, line, f"{tname} = ..."))
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        args = node.args
        positional = args.posonlyargs + args.args
        pairs = list(
            zip(positional[len(positional) - len(args.defaults) :], args.defaults, strict=False)
        )
        pairs += [
            (a, d) for a, d in zip(args.kwonlyargs, args.kw_defaults, strict=False) if d is not None
        ]
        for a, d in pairs:
            out.extend(_flag_signal(scope, a.arg, d, line, f"def {node.name}({a.arg}=...)"))
    return out


def _flag_signal(scope: str, name: str, value: ast.AST, line: int, where: str) -> list[Signal]:
    if not isinstance(value, ast.Constant) or not isinstance(value.value, bool):
        if name == "cert_reqs" and "CERT_NONE" in unparse(value):
            return [
                Signal(
                    "tls_verification_disabled",
                    scope,
                    f"{name}=CERT_NONE",
                    line,
                    f"{where} disables certificate checks",
                )
            ]
        return []
    v = value.value
    if name in TLS_KW and v is False:
        return [
            Signal(
                "tls_verification_disabled",
                scope,
                f"{name}=False",
                line,
                f"{where}: `{name}=False` disables TLS verification",
            )
        ]
    if INSECURE_FLAG_RE.match(name) and v is True:
        return [
            Signal(
                "security_default_disabled", scope, f"{name}=True", line, f"{where}: `{name}=True`"
            )
        ]
    if SEC_FLAG_RE.search(name) and not INSECURE_FLAG_RE.match(name) and v is False:
        return [
            Signal(
                "security_default_disabled",
                scope,
                f"{name}=False",
                line,
                f"{where}: `{name}=False`",
            )
        ]
    return []


# --------------------------------------------------------------------------- driver


def analyze_security(ctx: PatchContext) -> list[Finding]:
    c = ctx.contract
    out: list[Finding] = []
    for fc in ctx.python_files():
        if fc.new_path is None or is_test_path(fc.new_path):
            continue
        head = ctx.head_ast(fc)
        if head is None:
            if ctx.head_bytes(fc) is not None and fc.path.endswith(".py"):
                out.append(
                    finding(
                        "unparseable_python",
                        c,
                        "file does not parse at head; security analysis skipped",
                        file=fc.path,
                    )
                )
            continue
        base = ctx.base_ast(fc) if fc.old_path and not is_test_path(fc.old_path) else None
        # ---- introduced dangerous constructs
        before = Counter((s.code, s.scope, s.text) for s in (_signals(base) if base else []))
        for s in sorted(_signals(head), key=lambda s: (s.line, s.code, s.text)):
            key = (s.code, s.scope, s.text)
            if before[key] > 0:
                before[key] -= 1
                continue
            out.append(finding(s.code, c, s.detail, file=fc.path, line=s.line, after=s.text))
        if base is None:
            continue
        # ---- removed defensive facts, per function
        head_funcs = {i.qualname: i.node for i in iter_functions(head)}
        for info in iter_functions(base):
            hn = head_funcs.get(info.qualname)
            if hn is None:
                continue
            fb, fh = _func_facts(info.node), _func_facts(hn)
            q = info.qualname
            lost_auth = fb.auth - fh.auth - _helper_auth(hn, head_funcs)
            if lost_auth:
                out.append(
                    finding(
                        "auth_check_removed",
                        c,
                        f"{q}: authorization/denial check(s) removed: "
                        f"{', '.join(sorted(lost_auth))}",
                        file=fc.path,
                        line=hn.lineno,
                        before=", ".join(sorted(lost_auth)),
                    )
                )
            lost_decos = fb.auth_decos - fh.auth_decos
            if lost_decos:
                out.append(
                    finding(
                        "auth_decorator_removed",
                        c,
                        f"{q}: auth decorator removed: {', '.join(sorted(lost_decos))}",
                        file=fc.path,
                        line=hn.lineno,
                        before=", ".join(sorted(lost_decos)),
                    )
                )
            new_exempt = fh.exempt_decos - fb.exempt_decos
            if new_exempt:
                out.append(
                    finding(
                        "auth_decorator_removed",
                        c,
                        f"{q}: exemption decorator added: {', '.join(sorted(new_exempt))}",
                        file=fc.path,
                        line=hn.lineno,
                        after=", ".join(sorted(new_exempt)),
                    )
                )
            if fh.compare_digest < fb.compare_digest:
                out.append(
                    finding(
                        "constant_time_compare_removed",
                        c,
                        f"{q}: compare_digest removed (timing-safe comparison lost)",
                        file=fc.path,
                        line=hn.lineno,
                    )
                )
            lost_val = fb.validation - fh.validation
            if lost_val:
                out.append(
                    finding(
                        "input_validation_removed",
                        c,
                        f"{q}: validation removed: {', '.join(sorted(lost_val))}",
                        file=fc.path,
                        line=hn.lineno,
                        before=", ".join(sorted(lost_val)),
                    )
                )
            lost_path = fb.path_guards - fh.path_guards
            if lost_path:
                out.append(
                    finding(
                        "path_restriction_weakened",
                        c,
                        f"{q}: path containment check removed: {', '.join(sorted(lost_path))}",
                        file=fc.path,
                        line=hn.lineno,
                    )
                )
    return out
