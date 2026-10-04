"""Throwaway checkout of the exact head commit for evidence execution.

Evidence must come from the commit being judged, not from whatever happens to
be in the developer's working tree (uncommitted edits, untracked files).
"""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from aicrg.git.repo import GitError, Repo, run_git


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
