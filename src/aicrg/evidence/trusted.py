"""Trusted evidence: acceptance evidence the candidate patch has no authority over.

A candidate's own tests come from the candidate. A reward-hacking agent can
change the implementation *and* weaken the tests that judge it, and the
candidate test run is then green. Trusted evidence closes that gap: the
contract (read from the base) names evidence whose *content* comes from
somewhere the patch cannot write:

``source: base``    files matching ``paths`` are taken from the base commit.
                    Whatever the candidate did to those paths (edited,
                    deleted, added files under them, replaced a directory
                    with a symlink) is discarded before the command runs.
``source: bundle``  an immutable directory or tar archive, pinned by an
                    ``aicrg-tree-v1`` SHA-256 digest in the base contract and
                    mounted at ``mount`` inside the workspace. A wrong digest
                    is ERROR; the bundle is never used unverified.

The trusted files are overlaid on a fresh checkout of the candidate head, then
the trusted command runs against the candidate implementation.

What this does **not** remove: the trusted command still imports the candidate
code, and candidate code can detect it is under test or patch the test runner
(``conftest.py`` outside the trusted paths, ``sitecustomize``, plugins). Use
pytest's ``-c <trusted ini>`` and ``--confcutdir`` (or ``-p no:...``) in the
trusted command, and include runner configuration in ``paths``. Patch-level
analysis still reports changes to collection hooks and test configuration.
"""

from __future__ import annotations

import hashlib
import io
import os
import stat
import tarfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from aicrg.evidence.workspace import list_files, safe_remove, safe_write
from aicrg.git.repo import Repo
from aicrg.globmatch import match_any

TREE_DIGEST_VERSION = "aicrg-tree-v1"
MAX_BUNDLE_BYTES = 512 * 1024 * 1024


class TrustedEvidenceError(RuntimeError):
    """Trusted evidence cannot be materialised as pinned. Maps to ERROR."""


Entries = dict[str, tuple[bytes, bool]]  # path -> (content, executable)


def _check_rel(rel: str) -> str:
    p = PurePosixPath(rel)
    if p.is_absolute() or not p.parts or any(x in ("..", "") for x in p.parts):
        raise TrustedEvidenceError(f"unsafe path in trusted evidence: {rel!r}")
    if p.parts[0] == ".git":
        raise TrustedEvidenceError(f"trusted evidence may not contain .git: {rel!r}")
    return p.as_posix()


def tree_digest(entries: Entries) -> str:
    """``sha256:`` over a sorted manifest of (mode, content sha256, path) lines."""
    h = hashlib.sha256(TREE_DIGEST_VERSION.encode() + b"\n")
    for rel in sorted(entries):
        data, exe = entries[rel]
        mode = "100755" if exe else "100644"
        h.update(f"{mode} {hashlib.sha256(data).hexdigest()} {rel}\n".encode())
    return "sha256:" + h.hexdigest()


def _dir_entries(root: Path) -> Entries:
    out: Entries = {}
    total = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for d in dirnames:
            if os.path.islink(os.path.join(dirpath, d)):
                raise TrustedEvidenceError(f"bundle contains a symlink: {d}")
        for name in filenames:
            full = os.path.join(dirpath, name)
            st = os.lstat(full)
            if not stat.S_ISREG(st.st_mode):
                raise TrustedEvidenceError(f"bundle contains a non-regular file: {full}")
            rel = _check_rel(Path(full).relative_to(root).as_posix())
            total += st.st_size
            if total > MAX_BUNDLE_BYTES:
                raise TrustedEvidenceError("bundle exceeds size limit")
            with open(full, "rb") as fh:
                out[rel] = (fh.read(), bool(st.st_mode & 0o111))
    return out


def _tar_entries(path: Path) -> Entries:
    out: Entries = {}
    total = 0
    try:
        with tarfile.open(path, "r:*") as tf:
            for m in tf.getmembers():
                if m.isdir():
                    continue
                if not m.isfile():
                    raise TrustedEvidenceError(
                        f"bundle archive member is not a regular file: {m.name}"
                    )
                rel = _check_rel(m.name.removeprefix("./"))
                total += m.size
                if total > MAX_BUNDLE_BYTES:
                    raise TrustedEvidenceError("bundle exceeds size limit")
                fh = tf.extractfile(m)
                if fh is None:
                    raise TrustedEvidenceError(f"cannot read bundle member {m.name}")
                if rel in out:
                    raise TrustedEvidenceError(f"duplicate bundle member {rel}")
                out[rel] = (fh.read(), bool(m.mode & 0o111))
    except (tarfile.TarError, OSError) as exc:
        raise TrustedEvidenceError(f"cannot read bundle archive {path}: {exc}") from exc
    return out


def read_bundle(path: Path) -> Entries:
    if path.is_symlink():
        raise TrustedEvidenceError(f"bundle path is a symlink: {path}")
    if path.is_dir():
        return _dir_entries(path)
    if path.is_file():
        return _tar_entries(path)
    raise TrustedEvidenceError(f"bundle not found: {path}")


def load_bundle(path: Path, expected_digest: str) -> Entries:
    entries = read_bundle(path)
    if not entries:
        raise TrustedEvidenceError(f"bundle {path} is empty")
    actual = tree_digest(entries)
    if actual != expected_digest:
        raise TrustedEvidenceError(
            f"bundle digest mismatch for {path}: contract pins {expected_digest}, "
            f"bundle is {actual}"
        )
    return entries


def base_entries(repo: Repo, commit: str, patterns: tuple[str, ...]) -> Entries:
    """Every regular file at ``commit`` whose path matches ``patterns``."""
    out: Entries = {}
    raw = repo.git("ls-tree", "-r", "-z", "--full-tree", commit)
    for rec in raw.split(b"\0"):
        if not rec:
            continue
        meta, _, path_b = rec.partition(b"\t")
        mode, kind, _sha = meta.decode().split()
        path = path_b.decode("utf-8", "surrogateescape")
        if kind != "blob" or match_any(path, patterns) is None:
            continue
        if mode == "120000":
            raise TrustedEvidenceError(f"trusted base path is a symlink: {path}")
        data = repo.read_blob(commit, path)
        if data is None:
            raise TrustedEvidenceError(f"cannot read trusted file {path} at {commit[:12]}")
        out[_check_rel(path)] = (data, mode == "100755")
    return out


@dataclass(slots=True)
class Overlay:
    """What materialisation did, for the receipt."""

    name: str
    source: str
    digest: str
    files: int
    candidate_replaced: list[str] = field(default_factory=list)
    candidate_removed: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, object]:
        return {
            "name": self.name,
            "source": self.source,
            "digest": self.digest,
            "files": self.files,
            "candidate_files_replaced": self.candidate_replaced[:50],
            "candidate_files_removed": self.candidate_removed[:50],
        }


def _read_ws(ws: Path, rel: str) -> bytes | None:
    p = ws / rel
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(st.st_mode):
        return b"\0<not a regular file>"
    return p.read_bytes()


def overlay_base(ws: Path, name: str, patterns: tuple[str, ...], entries: Entries) -> Overlay:
    """Make ``patterns`` inside ``ws`` exactly equal to the base content."""
    ov = Overlay(name, "base", tree_digest(entries), len(entries))
    for rel in list_files(ws):
        if match_any(rel, patterns) is not None and rel not in entries:
            safe_remove(ws, rel)
            ov.candidate_removed.append(rel)
    for rel, (data, exe) in sorted(entries.items()):
        if _read_ws(ws, rel) != data:
            ov.candidate_replaced.append(rel)
        safe_write(ws, rel, data, exe)
    return ov


def overlay_bundle(ws: Path, name: str, mount: str, entries: Entries, digest: str) -> Overlay:
    """Replace the ``mount`` subtree of ``ws`` with the bundle's files."""
    mount = _check_rel(mount)
    ov = Overlay(name, "bundle", digest, len(entries))
    prefix = mount + "/"
    for rel in list_files(ws):
        if rel == mount or rel.startswith(prefix):
            target = rel[len(prefix) :] if rel.startswith(prefix) else ""
            if target not in entries:
                ov.candidate_removed.append(rel)
    safe_remove(ws, mount)
    for rel, (data, exe) in sorted(entries.items()):
        safe_write(ws, f"{mount}/{rel}", data, exe)
    return ov


def bundle_from_bytes(files: dict[str, bytes]) -> bytes:
    """Build a deterministic tar archive (test and tooling helper)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for rel in sorted(files):
            info = tarfile.TarInfo(rel)
            info.size = len(files[rel])
            info.mode = 0o644
            info.mtime = 0
            tf.addfile(info, io.BytesIO(files[rel]))
    return buf.getvalue()
