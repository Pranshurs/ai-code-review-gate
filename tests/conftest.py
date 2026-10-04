from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from collections.abc import Callable
from pathlib import Path

import pytest

GIT_ENV = {
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
    "GIT_CONFIG_NOSYSTEM": "1",
}


class GitRepo:
    def __init__(self, root: Path) -> None:
        self.root = root
        root.mkdir(parents=True, exist_ok=True)
        self.git("init", "-q", "-b", "main")

    def git(self, *args: str) -> str:
        out = subprocess.run(
            ["git", *args],
            cwd=self.root,
            env={**os.environ, **GIT_ENV},
            capture_output=True,
            text=True,
            check=True,
        )
        return out.stdout.strip()

    def write(self, files: dict[str, str]) -> None:
        for rel, content in files.items():
            p = self.root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(textwrap.dedent(content).lstrip("\n"))

    def commit(
        self, files: dict[str, str] | None = None, delete: tuple[str, ...] = (), msg: str = "c"
    ) -> str:
        self.write(files or {})
        for rel in delete:
            (self.root / rel).unlink()
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", msg)
        return self.git("rev-parse", "HEAD")


# Variables a CI runner sets that change the gate's behaviour (gate._ci_context,
# doctor's API access). Tests must not inherit the runner's values: under GitHub
# Actions every fixture receipt would otherwise be bound to *this* repository's
# CI commit, and attestation tests fail only in CI. Tests that exercise CI
# provenance set these explicitly.
AMBIENT_CI_ENV = (
    "GITHUB_ACTIONS",
    "GITHUB_REPOSITORY",
    "GITHUB_SHA",
    "GITHUB_REF",
    "GITHUB_EVENT_NAME",
    "GITHUB_WORKFLOW_REF",
    "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT",
    "GH_TOKEN",
    "GITHUB_TOKEN",
)


@pytest.fixture(autouse=True)
def _no_ambient_ci(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in AMBIENT_CI_ENV:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def repo(tmp_path: Path) -> GitRepo:
    return GitRepo(tmp_path / "r")


@pytest.fixture
def gate(repo: GitRepo) -> Callable[..., object]:
    """Run the gate on main..HEAD of ``repo`` (call after committing base on main)."""
    from aicrg.gate import GateOptions, run_gate

    def _run(**kw: object) -> object:
        opts = GateOptions(base=str(kw.pop("base", "main")), head=str(kw.pop("head", "HEAD")))
        for k, v in kw.items():
            setattr(opts, k, v)
        return run_gate(opts, cwd=repo.root)

    return _run


POLICY_NO_CHECKS = """
version: 1
"""

# A trivial executed check: lets tests exercise analysis without the
# "high-risk patch with no evidence" rule dominating the decision.
POLICY_OK = f"""
version: 1
required_checks:
  - name: noop
    command: [{sys.executable!r}, -c, "pass"]
"""

POLICY_PYTEST = f"""
version: 1
required_checks:
  - name: tests
    command: [{sys.executable!r}, -m, pytest, -q, -p, no:cacheprovider]
"""


def codes(result: object, *, include_advisory: bool = False) -> set[str]:
    from aicrg.model import Severity

    return {
        f.code
        for f in result.findings  # type: ignore[attr-defined]
        if include_advisory or f.severity is not Severity.ADVISORY
    }
