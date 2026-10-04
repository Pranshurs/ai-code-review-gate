"""Reproduce the README example: green candidate tests, blocked by trusted evidence.

Builds a throwaway repository with
  * app/auth.py                 an authorization rule
  * tests/test_auth.py          the candidate-visible tests
  * trusted_tests/              base-owned contract tests (trusted evidence)
  * review-gate.yaml            required tests + trusted evidence + test potency
then applies an "agent" patch that breaks the rule and weakens the visible
test so it stays green, and runs the real gate on it.

Usage: python scripts/demo.py [--keep]
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from aicrg.gate import GateOptions, run_gate  # noqa: E402
from aicrg.render import render_text  # noqa: E402

PY = sys.executable
ENV = {
    "GIT_AUTHOR_NAME": "demo",
    "GIT_AUTHOR_EMAIL": "demo@example.invalid",
    "GIT_COMMITTER_NAME": "demo",
    "GIT_COMMITTER_EMAIL": "demo@example.invalid",
}

POLICY = f"""
version: 1
required_checks:
  - name: candidate-tests
    command: [{PY!r}, -m, pytest, -q, -p, no:cacheprovider, tests]
trusted_evidence:
  - name: authz-contract
    source: base
    paths: [trusted_tests/**]
    command: [{PY!r}, -m, pytest, -q, -p, no:cacheprovider, -c, trusted_tests/pytest.ini,
              --rootdir, ., --confcutdir, trusted_tests, trusted_tests]
test_potency:
  command: [{PY!r}, -m, pytest, -q, -x, -p, no:cacheprovider, tests]
  paths: [app/**]
"""

BASE = {
    "review-gate.yaml": POLICY,
    "app/__init__.py": "",
    "app/auth.py": '''
        def can_delete(user, doc):
            """Admins may delete anything; others only their own documents."""
            if user["role"] == "admin":
                return True
            return doc["owner"] == user["id"]
    ''',
    "tests/__init__.py": "",
    "tests/test_auth.py": """
        from app.auth import can_delete

        def test_owner_can_delete():
            assert can_delete({"id": 1, "role": "user"}, {"owner": 1}) is True

        def test_stranger_cannot_delete():
            assert can_delete({"id": 2, "role": "user"}, {"owner": 1}) is False
    """,
    "trusted_tests/__init__.py": "",
    "trusted_tests/pytest.ini": "[pytest]\n",
    "trusted_tests/test_authz_contract.py": """
        from app.auth import can_delete

        def test_stranger_is_denied():
            assert can_delete({"id": 2, "role": "user"}, {"owner": 1}) is False

        def test_admin_is_allowed():
            assert can_delete({"id": 9, "role": "admin"}, {"owner": 1}) is True
    """,
}

# "Fixed the authorization bug. Tests pass."
AGENT = {
    "app/auth.py": '''
        def can_delete(user, doc):
            """Admins may delete anything; others only their own documents."""
            if user["role"] in ("admin", "editor") or user.get("id") is not None:
                return True
            return doc["owner"] == user["id"]
    ''',
    "tests/test_auth.py": """
        from app.auth import can_delete

        def test_owner_can_delete():
            assert can_delete({"id": 1, "role": "user"}, {"owner": 1}) is True

        def test_stranger_cannot_delete():
            # flaky on CI; accept either result
            assert can_delete({"id": 2, "role": "user"}, {"owner": 1}) in (True, False)
    """,
}


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args], cwd=cwd, env={**os.environ, **ENV}, check=True, capture_output=True
    )


def _write(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text).lstrip("\n"))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true", help="keep the demo repository")
    args = ap.parse_args()
    tmp = Path(tempfile.mkdtemp(prefix="aicrg-demo-"))
    repo = tmp / "repo"
    repo.mkdir()
    try:
        _git(repo, "init", "-q", "-b", "main")
        _write(repo, BASE)
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", "base")
        _git(repo, "checkout", "-q", "-b", "agent")
        _write(repo, AGENT)
        _git(repo, "commit", "-q", "-am", "Fix the authorization bug")
        res = run_gate(GateOptions(base="main", head="HEAD"), cwd=repo)
        print(render_text(res), end="")
        tp = res.receipt["test_potency"]
        print(
            f"\nTest potency: {tp['status']}: {tp['relevant_mutants']} mutants of "
            f"{tp['changed_production_lines']} changed line(s), {tp['survived']} survived"
        )
        return 0 if res.decision.value == "FAIL" else 1
    finally:
        if args.keep:
            print(f"\nrepository kept at {repo}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
