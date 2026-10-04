"""Test-runner, coverage and checker configuration that a patch can loosen.

A patch does not have to touch a test to stop it running: ``addopts =
--ignore=tests/test_auth.py`` or ``fail_under = 0`` is enough. Neither does it
have to fix a type error: ``# mypy: ignore-errors`` will do.
"""

from __future__ import annotations

import configparser
import re
import shlex
import tomllib
from dataclasses import dataclass, field
from typing import Any

from aicrg.analysis.context import PatchContext
from aicrg.git.diff import FileChange
from aicrg.model import Finding
from aicrg.rules import finding

CONFIG_FILES = (
    "pyproject.toml",
    "pytest.ini",
    "setup.cfg",
    "tox.ini",
    ".coveragerc",
    "ruff.toml",
    ".ruff.toml",
    "mypy.ini",
    ".mypy.ini",
)

_DESELECT_OPTS = (
    "--ignore",
    "--ignore-glob",
    "--deselect",
    "-k",
    "-m",
    "--co",
    "--collect-only",
    "--continue-on-collection-errors",
)

_MYPY_STRICT_FLAGS = re.compile(
    r"^(strict|disallow_\w+|warn_\w+|check_untyped_defs|strict_\w+|no_implicit_\w+|"
    r"extra_checks|no_implicit_reexport)$"
)


@dataclass(slots=True)
class CheckerConfig:
    addopts: list[str] = field(default_factory=list)
    testpaths: list[str] = field(default_factory=list)
    norecursedirs: list[str] = field(default_factory=list)
    fail_under: float | None = None
    mypy: dict[str, Any] = field(default_factory=dict)
    mypy_ignored_modules: set[str] = field(default_factory=set)
    ruff_select: set[str] = field(default_factory=set)
    ruff_ignore: set[str] = field(default_factory=set)


def _split(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str):
        try:
            return shlex.split(value)
        except ValueError:
            return value.split()
    return []


def _as_bool(v: Any) -> Any:
    if isinstance(v, str):
        low = v.strip().lower()
        if low in ("true", "1", "yes", "on"):
            return True
        if low in ("false", "0", "no", "off"):
            return False
    return v


def _fail_under_from_addopts(opts: list[str]) -> float | None:
    for i, tok in enumerate(opts):
        if tok.startswith("--cov-fail-under="):
            try:
                return float(tok.split("=", 1)[1])
            except ValueError:
                return None
        if tok == "--cov-fail-under" and i + 1 < len(opts):
            try:
                return float(opts[i + 1])
            except ValueError:
                return None
    return None


def parse_config(path: str, text: str | None) -> CheckerConfig | None:
    """Returns ``None`` when the file exists but cannot be parsed."""
    cfg = CheckerConfig()
    if text is None:
        return cfg
    name = path.rsplit("/", 1)[-1]
    try:
        if name.endswith(".toml"):
            data = tomllib.loads(text)
            if name == "pyproject.toml":
                tool = data.get("tool", {})
                pt = tool.get("pytest", {}).get("ini_options", {})
                cov = tool.get("coverage", {}).get("report", {})
                mypy = tool.get("mypy", {})
                ruff = tool.get("ruff", {})
            else:
                pt, cov, mypy, ruff = {}, {}, {}, data
            cfg.addopts = _split(pt.get("addopts", []))
            cfg.testpaths = _split(pt.get("testpaths", []))
            cfg.norecursedirs = _split(pt.get("norecursedirs", []))
            if "fail_under" in cov:
                cfg.fail_under = float(cov["fail_under"])
            cfg.mypy = {k: _as_bool(v) for k, v in mypy.items() if k != "overrides"}
            for ov in mypy.get("overrides", []) or []:
                if _as_bool(ov.get("ignore_errors")) is True:
                    mods = ov.get("module", [])
                    cfg.mypy_ignored_modules.update([mods] if isinstance(mods, str) else mods)
            lint = ruff.get("lint", {})
            cfg.ruff_select = set(lint.get("select", ruff.get("select", [])))
            ign: set[str] = set()
            for src in (ruff, lint):
                ign.update(src.get("ignore", []))
                ign.update(src.get("extend-ignore", []))
                for pattern, codes in (src.get("per-file-ignores", {}) or {}).items():
                    ign.update(f"{pattern}:{c}" for c in codes)
            cfg.ruff_ignore = ign
        else:
            cp = configparser.ConfigParser(interpolation=None)
            cp.read_string(text)
            section = {"pytest.ini": "pytest", "tox.ini": "pytest", "setup.cfg": "tool:pytest"}.get(
                name
            )
            if section and cp.has_section(section):
                cfg.addopts = _split(cp.get(section, "addopts", fallback=""))
                cfg.testpaths = _split(cp.get(section, "testpaths", fallback=""))
                cfg.norecursedirs = _split(cp.get(section, "norecursedirs", fallback=""))
            cov_section = "report" if name == ".coveragerc" else "coverage:report"
            if cp.has_section(cov_section) and cp.has_option(cov_section, "fail_under"):
                cfg.fail_under = float(cp.get(cov_section, "fail_under"))
            if cp.has_section("mypy"):
                cfg.mypy = {k: _as_bool(v) for k, v in cp.items("mypy")}
            for sec in cp.sections():
                if (
                    sec.startswith("mypy-")
                    and _as_bool(cp.get(sec, "ignore_errors", fallback="")) is True
                ):
                    cfg.mypy_ignored_modules.add(sec[len("mypy-") :])
        if cfg.fail_under is None:
            cfg.fail_under = _fail_under_from_addopts(cfg.addopts)
    except (tomllib.TOMLDecodeError, configparser.Error, ValueError, AttributeError, TypeError):
        return None
    return cfg


def _new_deselect_opts(before: list[str], after: list[str]) -> list[str]:
    old = list(before)
    out: list[str] = []
    for i, tok in enumerate(after):
        if tok in old:
            old.remove(tok)
            continue
        if any(tok == o or tok.startswith(o + "=") for o in _DESELECT_OPTS):
            nxt = after[i + 1] if i + 1 < len(after) and "=" not in tok else ""
            out.append(f"{tok} {nxt}".strip())
    return out


def analyze_config(ctx: PatchContext) -> list[Finding]:
    out: list[Finding] = []
    contract = ctx.contract
    for fc in ctx.patch.files:
        name = fc.path.rsplit("/", 1)[-1]
        if name not in CONFIG_FILES:
            continue
        before = parse_config(fc.path, ctx.base_text(fc))
        after = parse_config(fc.path, ctx.head_text(fc))
        if before is None or after is None:
            out.append(
                finding(
                    "config_unparseable",
                    contract,
                    f"{name} could not be parsed; config analysis incomplete",
                    file=fc.path,
                )
            )
            continue
        out.extend(_compare_config(fc, before, after, ctx))
    return out


def _compare_config(
    fc: FileChange, b: CheckerConfig, a: CheckerConfig, ctx: PatchContext
) -> list[Finding]:
    c = ctx.contract
    out: list[Finding] = []
    for opt in _new_deselect_opts(b.addopts, a.addopts):
        out.append(
            finding(
                "test_config_excludes_tests",
                c,
                f"pytest addopts now include `{opt}`",
                file=fc.path,
                after=opt,
            )
        )
    dropped = [p for p in b.testpaths if p not in a.testpaths]
    if dropped and b.testpaths:
        out.append(
            finding(
                "test_config_excludes_tests",
                c,
                f"pytest testpaths no longer include {dropped}",
                file=fc.path,
            )
        )
    added_nr = [p for p in a.norecursedirs if p not in b.norecursedirs]
    if added_nr:
        out.append(
            finding(
                "test_config_excludes_tests",
                c,
                f"pytest norecursedirs now skip {added_nr}",
                file=fc.path,
            )
        )
    if b.fail_under is not None and (a.fail_under is None or a.fail_under < b.fail_under):
        out.append(
            finding(
                "coverage_threshold_lowered",
                c,
                f"coverage fail_under {b.fail_under} -> {a.fail_under}",
                file=fc.path,
            )
        )
    for key, val in sorted(b.mypy.items()):
        if _MYPY_STRICT_FLAGS.match(key) and val is True and a.mypy.get(key) is not True:
            out.append(
                finding("checker_config_loosened", c, f"mypy `{key}` turned off", file=fc.path)
            )
    if a.mypy.get("ignore_errors") is True and b.mypy.get("ignore_errors") is not True:
        out.append(
            finding("checker_config_loosened", c, "mypy ignore_errors enabled", file=fc.path)
        )
    new_ignored = sorted(a.mypy_ignored_modules - b.mypy_ignored_modules)
    if new_ignored:
        out.append(
            finding(
                "checker_config_loosened",
                c,
                f"mypy ignore_errors for modules {new_ignored}",
                file=fc.path,
            )
        )
    if b.ruff_select and (b.ruff_select - a.ruff_select):
        out.append(
            finding(
                "checker_config_loosened",
                c,
                f"ruff rules deselected: {sorted(b.ruff_select - a.ruff_select)}",
                file=fc.path,
            )
        )
    grown = sorted(a.ruff_ignore - b.ruff_ignore)
    if grown:
        out.append(
            finding("checker_config_loosened", c, f"ruff ignores added: {grown[:10]}", file=fc.path)
        )
    return out


# --------------------------------------------------------------------------- suppressions

_FILE_LEVEL = re.compile(
    r"#\s*(mypy:\s*ignore-errors|ruff:\s*noqa\s*$|flake8:\s*noqa\s*$|pylint:\s*skip-file|"
    r"pyright:\s*(basic|ignore)|type:\s*ignore\s*$)"
)
_SECURITY = re.compile(r"#\s*(nosec\b|nosemgrep\b|noqa:\s*[^#]*\bS\d{3})")
_INLINE = re.compile(r"#\s*(type:\s*ignore(?!\[)|noqa(?!:)|pragma:\s*no\s*cover)")


def analyze_suppressions(ctx: PatchContext) -> list[Finding]:
    out: list[Finding] = []
    c = ctx.contract
    for fc in ctx.patch.files:
        if not fc.path.endswith((".py", ".pyi")) or fc.binary:
            continue
        removed_text = {t.strip() for t in fc.removed.values()}
        for ln, text in sorted(fc.added.items()):
            if "#" not in text or text.strip() in removed_text:
                continue
            comment = text[text.index("#") :]
            stripped = text.strip()
            if _SECURITY.search(comment):
                out.append(
                    finding(
                        "security_suppression_added",
                        c,
                        "security scanner suppression added",
                        file=fc.path,
                        line=ln,
                        after=stripped,
                    )
                )
            elif _FILE_LEVEL.search(comment) and (
                stripped.startswith("#")
                and (ln <= 10 or "ignore-errors" in comment or "skip-file" in comment)
            ):
                out.append(
                    finding(
                        "checker_suppression_added",
                        c,
                        "file-wide checker suppression added",
                        file=fc.path,
                        line=ln,
                        after=stripped,
                    )
                )
            elif _INLINE.search(comment):
                out.append(
                    finding(
                        "inline_suppression_added",
                        c,
                        "untargeted inline suppression added",
                        file=fc.path,
                        line=ln,
                        after=stripped,
                    )
                )
    return out
