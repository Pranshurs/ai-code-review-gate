"""Throwaway checkouts of exact commits for evidence execution.

Evidence must come from the commit being judged, not from whatever happens to
be in the developer's working tree (uncommitted edits, untracked files).

Two forms:

``worktree``  a detached ``git worktree`` (local trusted-code mode; keeps git
              available to the project's own tooling).
``export``    the commit's tree written into a plain directory with a private
              index. There is no ``.git`` link back into the host repository,
              so code running in it cannot rewrite the gate's repository
              (refs, hooks, ``core.fsmonitor``...). Used for container mode.

``safe_write``/``safe_remove`` modify a workspace without ever following a
symlink planted by the patch: a candidate that turns ``trusted_tests`` into a
symlink to ``/home/runner`` must not be able to redirect the trusted overlay.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

from aicrg.git.repo import _STABLE, GitError, Repo, _git_env, run_git


class WorkspaceError(RuntimeError):
    pass


@contextmanager
def head_worktree(repo: Repo, head: str) -> Iterator[Path]:
    tmp = Path(tempfile.mkdtemp(prefix="aicrg-worktree-"))
    path = tmp / "head"
    try:
        repo.git("worktree", "add", "--detach", "--force", str(path), head)
        actual = run_git(path, "rev-parse", "HEAD").decode().strip()
        if actual != head:
            raise GitError(f"worktree is at {actual[:12]}, expected {head[:12]}")
        if run_git(path, "status", "--porcelain").strip():
            raise GitError("fresh worktree is not clean")
        yield path
    finally:
        repo.git("worktree", "remove", "--force", str(path), check=False)
        repo.git("worktree", "prune", check=False)
        shutil.rmtree(tmp, ignore_errors=True)


@contextmanager
def exported_tree(repo: Repo, commit: str) -> Iterator[Path]:
    tmp = Path(tempfile.mkdtemp(prefix="aicrg-export-"))
    path = tmp / "ws"
    index = tmp / "index"
    try:
        path.mkdir()
        env_index = {"GIT_INDEX_FILE": str(index)}
        _git_with_env(repo, env_index, "read-tree", commit)
        _git_with_env(
            repo,
            env_index,
            "-c",
            "core.autocrlf=false",
            f"--work-tree={path}",
            "checkout-index",
            "--all",
            "--force",
        )
        index.unlink(missing_ok=True)
        yield path
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _git_with_env(repo: Repo, extra: dict[str, str], *args: str) -> None:
    env = {**_git_env(), **extra}
    proc = subprocess.run(
        ["git", *_STABLE, *args],
        cwd=repo.root,
        env=env,
        capture_output=True,
        check=False,
        timeout=600,
    )
    if proc.returncode != 0:
        raise GitError(
            f"git {' '.join(args[:3])} failed: {proc.stderr.decode('utf-8', 'replace').strip()}"
        )


@contextmanager
def checkout(repo: Repo, commit: str, mode: str) -> Iterator[Path]:
    if mode == "worktree":
        with head_worktree(repo, commit) as p:
            yield p
    elif mode == "export":
        with exported_tree(repo, commit) as p:
            yield p
    else:
        raise WorkspaceError(f"unknown workspace mode {mode!r}")


# --------------------------------------------------------------------------- safe edits


def _rel_parts(rel: str) -> tuple[str, ...]:
    p = PurePosixPath(rel)
    if p.is_absolute() or not p.parts or any(x in ("..", "") for x in p.parts):
        raise WorkspaceError(f"unsafe workspace path {rel!r}")
    if p.parts[0] == ".git":
        raise WorkspaceError(f"refusing to write into .git: {rel!r}")
    return p.parts


def _safe_parent(root: Path, parts: tuple[str, ...], create: bool) -> Path | None:
    """Walk to the parent directory of ``parts`` refusing every symlink on the way."""
    cur = root
    for part in parts[:-1]:
        nxt = cur / part
        try:
            st = os.lstat(nxt)
        except FileNotFoundError:
            if not create:
                return None
            nxt.mkdir()
            cur = nxt
            continue
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            if not create:
                return None
            # The patch put a symlink or file where trusted content needs a directory.
            _remove_entry(nxt)
            nxt.mkdir()
        cur = nxt
    return cur


def _remove_entry(p: Path) -> None:
    st = os.lstat(p)
    if stat.S_ISDIR(st.st_mode):
        shutil.rmtree(p)
    else:
        p.unlink()


def safe_write(root: Path, rel: str, data: bytes, executable: bool = False) -> None:
    parts = _rel_parts(rel)
    parent = _safe_parent(root, parts, create=True)
    assert parent is not None  # noqa: S101 - create=True always yields a directory
    target = parent / parts[-1]
    if os.path.lexists(target):
        _remove_entry(target)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    if executable:
        os.chmod(target, 0o755)  # noqa: S103 - keeps the trusted file executable


def safe_remove(root: Path, rel: str) -> bool:
    parts = _rel_parts(rel)
    parent = _safe_parent(root, parts, create=False)
    if parent is None:
        return False
    target = parent / parts[-1]
    if not os.path.lexists(target):
        return False
    _remove_entry(target)
    return True


def list_files(root: Path) -> list[str]:
    """Every non-directory entry under ``root`` (symlinks included, never followed)."""
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = Path(dirpath).relative_to(root)
        if rel_dir.parts[:1] == (".git",):
            continue
        dirnames[:] = [d for d in dirnames if not (rel_dir == Path(".") and d == ".git")]
        links = [d for d in dirnames if os.path.islink(os.path.join(dirpath, d))]
        for name in filenames + links:
            if rel_dir == Path(".") and name == ".git":
                continue
            out.append((rel_dir / name).as_posix())
    return sorted(out)
