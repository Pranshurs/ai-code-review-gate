"""Deterministic path globbing with explicit ``**`` semantics.

``fnmatch`` lets ``*`` cross ``/``, which makes ``src/*`` silently match
``src/a/b/c``. Contract paths must mean exactly what they say, so we compile
our own patterns:

* ``*``   any run of characters except ``/``
* ``?``   one character except ``/``
* ``**``  any number of whole path segments (including zero)
* a pattern without ``/`` matches the basename at any depth (``*.lock``)
* a leading ``./`` anchors the pattern at the repository root
  (``./review-gate.yaml`` matches only the root file)
"""

from __future__ import annotations

import re
from functools import lru_cache


class GlobError(ValueError):
    pass


@lru_cache(maxsize=1024)
def compile_glob(pattern: str) -> re.Pattern[str]:
    if not pattern or pattern.startswith("/") or "\\" in pattern:
        raise GlobError(f"invalid path pattern {pattern!r}: must be a relative POSIX glob")
    if "[" in pattern or "]" in pattern or "{" in pattern:
        raise GlobError(f"invalid path pattern {pattern!r}: character classes/braces unsupported")
    root_anchored = pattern.startswith("./")
    if root_anchored:
        pattern = pattern[2:]
        if not pattern or pattern.startswith("/") or pattern.startswith("./"):
            raise GlobError("invalid path pattern: nothing after './'")
    anchored = root_anchored or "/" in pattern.rstrip("/")
    pat = pattern.rstrip("/") if pattern.endswith("/") else pattern
    if pattern.endswith("/"):
        pat += "/**"
    out: list[str] = []
    i = 0
    while i < len(pat):
        if pat.startswith("**/", i):
            out.append("(?:[^/]+/)*")
            i += 3
        elif pat.startswith("/**", i) and i + 3 == len(pat):
            out.append("(?:/.*)?")
            i += 3
        elif pat.startswith("**", i):
            out.append(".*")
            i += 2
        elif pat[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pat[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pat[i]))
            i += 1
    body = "".join(out)
    if not anchored:
        body = "(?:[^/]+/)*" + body
    # DOTALL + fullmatch: a path containing a newline (git allows it) must not slip
    # past `.*` or the `$`-before-trailing-newline rule.
    return re.compile(body, re.DOTALL)


def match(path: str, pattern: str) -> bool:
    return compile_glob(pattern).fullmatch(path) is not None


_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def has_control_chars(path: str) -> bool:
    """Tracked paths with control characters are refused by the gate (``unsafe_path_name``)."""
    return _CONTROL.search(path) is not None


def match_any(path: str, patterns: tuple[str, ...] | list[str]) -> str | None:
    """Return the first pattern matching ``path`` or ``None``."""
    for p in patterns:
        if match(path, p):
            return p
    return None
