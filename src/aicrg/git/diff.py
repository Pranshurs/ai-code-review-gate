"""Patch extraction: what exactly changed between two commits."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from aicrg.git.repo import Repo, sha256_hex

_DIFF_ARGS = (
    "--no-color",
    "--no-ext-diff",
    "--no-textconv",
    "--full-index",
    "--find-renames=50%",
    "--src-prefix=a/",
    "--dst-prefix=b/",
    "--no-relative",
)

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


@dataclass(slots=True)
class FileChange:
    status: str  # A, M, D, R, C, T
    old_path: str | None
    new_path: str | None
    added: dict[int, str] = field(default_factory=dict)  # head line -> text
    removed: dict[int, str] = field(default_factory=dict)  # base line -> text
    binary: bool = False
    similarity: int | None = None

    @property
    def path(self) -> str:
        p = self.new_path if self.new_path is not None else self.old_path
        if p is None:
            raise ValueError("file change without a path")
        return p

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(sorted({p for p in (self.old_path, self.new_path) if p is not None}))

    def status_word(self) -> str:
        return {
            "A": "added",
            "M": "modified",
            "D": "deleted",
            "R": "renamed",
            "C": "copied",
            "T": "type-changed",
        }.get(self.status, self.status)

    def to_json(self) -> dict[str, object]:
        return {
            "status": self.status,
            "old_path": self.old_path,
            "new_path": self.new_path,
            "added_lines": len(self.added),
            "removed_lines": len(self.removed),
            "binary": self.binary,
        }


@dataclass(slots=True)
class Patch:
    base: str  # merge-base actually diffed against
    head: str
    files: list[FileChange]
    digest: str  # sha256 of canonical full-index binary diff
    size_bytes: int

    def by_path(self) -> dict[str, FileChange]:
        return {f.path: f for f in self.files}


def _unquote(path: str) -> str:
    if len(path) >= 2 and path[0] == '"' and path[-1] == '"':
        raw = path[1:-1].encode("latin-1", "backslashreplace").decode("unicode_escape")
        return raw.encode("latin-1").decode("utf-8", "replace")
    return path


def extract_patch(repo: Repo, base: str, head: str) -> Patch:
    canonical = repo.git("diff", *_DIFF_ARGS, "--binary", base, head, "--")
    files = _name_status(repo, base, head)
    _attach_lines(repo, base, head, files)
    ordered = sorted(files.values(), key=lambda f: f.path)
    return Patch(
        base=base,
        head=head,
        files=ordered,
        digest="sha256:" + sha256_hex(canonical),
        size_bytes=len(canonical),
    )


def patch_digest(repo: Repo, base: str, head: str) -> str:
    canonical = repo.git("diff", *_DIFF_ARGS, "--binary", base, head, "--")
    return "sha256:" + sha256_hex(canonical)


def _name_status(repo: Repo, base: str, head: str) -> dict[str, FileChange]:
    raw = repo.git("diff", *_DIFF_ARGS, "--name-status", "-z", base, head, "--")
    tokens = raw.decode("utf-8", "surrogateescape").split("\0")
    files: dict[str, FileChange] = {}
    i = 0
    while i < len(tokens) and tokens[i]:
        status = tokens[i]
        code = status[0]
        if code in "RC":
            old, new = tokens[i + 1], tokens[i + 2]
            fc = FileChange(code, old, new, similarity=int(status[1:] or 0))
            i += 3
        else:
            p = tokens[i + 1]
            if code == "A":
                fc = FileChange("A", None, p)
            elif code == "D":
                fc = FileChange("D", p, None)
            else:
                fc = FileChange(code, p, p)
            i += 2
        files[fc.path] = fc
    return files


def _attach_lines(repo: Repo, base: str, head: str, files: dict[str, FileChange]) -> None:
    raw = repo.git("diff", *_DIFF_ARGS, "-U0", base, head, "--")
    current: FileChange | None = None
    old_ln = new_ln = 0
    pending_old: str | None = None
    for line in raw.decode("utf-8", "replace").split("\n"):
        if line.startswith("diff --git "):
            current = None
            pending_old = None
            continue
        if line.startswith("--- "):
            pending_old = None if line[4:] == "/dev/null" else _unquote(line[4:])[2:]
            continue
        if line.startswith("+++ "):
            target = None if line[4:] == "/dev/null" else _unquote(line[4:])[2:]
            key = target if target is not None else pending_old
            current = files.get(key) if key is not None else None
            continue
        if line.startswith("Binary files "):
            # Binary files have no ---/+++ header; match by any path in the line.
            for fc in files.values():
                if any(f"a/{p} and " in line or line.endswith(f"b/{p} differ") for p in fc.paths):
                    fc.binary = True
            continue
        m = _HUNK_RE.match(line)
        if m:
            old_ln = int(m.group(1))
            new_ln = int(m.group(3))
            # With -U0 a pure insertion reports the line *before*; a count of
            # zero means no lines on that side.
            if m.group(2) == "0":
                old_ln += 1
            if m.group(4) == "0":
                new_ln += 1
            continue
        if current is None or not line or line.startswith("\\"):
            continue
        if line[0] == "+":
            current.added[new_ln] = line[1:]
            new_ln += 1
        elif line[0] == "-":
            current.removed[old_ln] = line[1:]
            old_ln += 1
