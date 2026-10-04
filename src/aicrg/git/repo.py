"""Thin, explicit wrapper around the ``git`` CLI.

All revisions are resolved to full commit SHAs exactly once, at the start of a
gate run. Every later read uses those SHAs, never symbolic refs, so a branch
moving mid-evaluation cannot change what was evaluated.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

_SHA_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")

# Options that make git output independent of user configuration.
_STABLE = (
    "-c",
    "core.quotepath=false",
    "-c",
    "diff.noprefix=false",
    "-c",
    "diff.mnemonicPrefix=false",
    "-c",
    "diff.external=",
    "-c",
    "color.ui=false",
    "-c",
    "core.hooksPath=/dev/null",
)


class GitError(RuntimeError):
    pass


def _git_env() -> dict[str, str]:
    env = dict(os.environ)
    env.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_LFS_SKIP_SMUDGE": "1",
            "LC_ALL": "C",
            "GIT_PAGER": "cat",
        }
    )
    env.pop("GIT_DIR", None)
    env.pop("GIT_WORK_TREE", None)
    return env


def run_git(cwd: Path, *args: str, check: bool = True) -> bytes:
    try:
        proc = subprocess.run(
            ["git", *_STABLE, *args],
            cwd=cwd,
            capture_output=True,
            env=_git_env(),
            check=False,
            timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitError(f"git {' '.join(args[:2])} could not run: {exc}") from exc
    if check and proc.returncode != 0:
        msg = proc.stderr.decode("utf-8", "replace").strip()
        raise GitError(f"git {' '.join(args)} failed ({proc.returncode}): {msg}")
    return proc.stdout


def sanitize_remote_url(url: str) -> str:
    """Drop credentials from a remote URL before it is written to a receipt."""
    url = url.strip()
    if "://" in url:
        parts = urlsplit(url)
        host = parts.hostname or ""
        if parts.port:
            host = f"{host}:{parts.port}"
        cleaned = urlunsplit((parts.scheme, host, parts.path, "", ""))
        # Local proxy remotes embed the repo path; keep only the path tail.
        return cleaned.removesuffix(".git")
    # scp-like syntax: user@host:path
    if "@" in url.split(":", 1)[0]:
        url = url.split("@", 1)[1]
    return url.removesuffix(".git")


@dataclass(frozen=True, slots=True)
class Repo:
    root: Path

    @classmethod
    def discover(cls, path: Path) -> Repo:
        out = run_git(path, "rev-parse", "--show-toplevel")
        return cls(Path(out.decode().strip()))

    def git(self, *args: str, check: bool = True) -> bytes:
        return run_git(self.root, *args, check=check)

    def resolve_commit(self, rev: str) -> str:
        if rev.startswith("-"):
            raise GitError(f"refusing revision that looks like an option: {rev!r}")
        out = self.git("rev-parse", "--verify", "--end-of-options", f"{rev}^{{commit}}")
        sha = out.decode().strip()
        if not _SHA_RE.match(sha):
            raise GitError(f"unexpected rev-parse output for {rev!r}: {sha!r}")
        return sha

    def merge_base(self, a: str, b: str) -> str:
        out = self.git("merge-base", a, b, check=False).decode().strip()
        if not _SHA_RE.match(out):
            raise GitError(f"no merge-base between {a[:12]} and {b[:12]}")
        return out

    def tree_of(self, commit: str) -> str:
        return self.git("rev-parse", f"{commit}^{{tree}}").decode().strip()

    def identity(self) -> dict[str, object]:
        remote = self.git("config", "--get", "remote.origin.url", check=False).decode().strip()
        roots = self.git("rev-list", "--max-parents=0", "HEAD", check=False).decode().split()
        return {
            "remote": sanitize_remote_url(remote) if remote else None,
            "root_commits": sorted(roots),
        }

    def git_version(self) -> str:
        return self.git("--version").decode().strip()

    def head_sha(self) -> str:
        return self.resolve_commit("HEAD")

    def read_blob(self, commit: str, path: str) -> bytes | None:
        """File content at ``commit``; ``None`` if the path does not exist there."""
        proc = subprocess.run(
            ["git", *_STABLE, "cat-file", "blob", f"{commit}:{path}"],
            cwd=self.root,
            capture_output=True,
            env=_git_env(),
            check=False,
            timeout=120,
        )
        if proc.returncode != 0:
            # Distinguish "missing" from "git is broken".
            exists = subprocess.run(
                ["git", *_STABLE, "cat-file", "-e", commit],
                cwd=self.root,
                capture_output=True,
                env=_git_env(),
                check=False,
                timeout=60,
            )
            if exists.returncode != 0:
                raise GitError(f"commit {commit[:12]} is not readable")
            return None
        return proc.stdout

    def is_dirty(self) -> bool:
        out = self.git("status", "--porcelain", "--untracked-files=no", check=False)
        return bool(out.strip())


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
