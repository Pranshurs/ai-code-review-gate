"""Trusted evidence: acceptance evidence the candidate patch cannot control."""

import sys
from pathlib import Path

from aicrg.cli import main
from aicrg.evidence.trusted import (
    TrustedEvidenceError,
    bundle_from_bytes,
    load_bundle,
    read_bundle,
    tree_digest,
)
from aicrg.model import Decision, Severity
from tests.conftest import codes

PY = sys.executable

AUTH_OK = """
def can_delete(user, doc):
    if user["role"] == "admin":
        return True
    return doc["owner"] == user["id"]
"""

# The agent "fixes" a bug by allowing everyone to delete.
AUTH_BROKEN = """
def can_delete(user, doc):
    return True
"""

VISIBLE_TEST = """
from app.auth import can_delete

def test_owner_can_delete():
    assert can_delete({"id": 1, "role": "user"}, {"owner": 1}) is True

def test_stranger_cannot_delete():
    assert can_delete({"id": 2, "role": "user"}, {"owner": 1}) is False
"""

VISIBLE_TEST_WEAKENED = """
from app.auth import can_delete

def test_owner_can_delete():
    assert can_delete({"id": 1, "role": "user"}, {"owner": 1}) is True

def test_stranger_cannot_delete():
    assert can_delete({"id": 2, "role": "user"}, {"owner": 1}) in (True, False)
"""

TRUSTED_TEST = """
from app.auth import can_delete

def test_contract_stranger_is_denied():
    assert can_delete({"id": 2, "role": "user"}, {"owner": 1}) is False

def test_contract_admin_is_allowed():
    assert can_delete({"id": 9, "role": "admin"}, {"owner": 1}) is True
"""

# Trusted runner config: -c pins the ini (ignores the candidate's pyproject addopts),
# --confcutdir stops conftest discovery above trusted_tests/.
TRUSTED_CMD = (
    f"[{PY!r}, -m, pytest, -q, -p, no:cacheprovider, -c, trusted_tests/pytest.ini, "
    "--rootdir, ., --confcutdir, trusted_tests, trusted_tests]"
)


def _policy(extra: str = "") -> str:
    return f"""
version: 1
required_checks:
  - name: candidate-tests
    command: [{PY!r}, -m, pytest, -q, -p, no:cacheprovider, tests]
trusted_evidence:
  - name: auth-contract
    source: base
    paths: [trusted_tests/**]
    command: {TRUSTED_CMD}
{extra}
"""


def _base(repo, policy=None):
    repo.commit(
        {
            "review-gate.yaml": policy or _policy(),
            "app/__init__.py": "",
            "app/auth.py": AUTH_OK,
            "tests/__init__.py": "",
            "tests/test_auth.py": VISIBLE_TEST,
            "trusted_tests/__init__.py": "",
            "trusted_tests/pytest.ini": "[pytest]\n",
            "trusted_tests/test_auth_contract.py": TRUSTED_TEST,
        }
    )
    repo.git("checkout", "-q", "-b", "agent")


class TestTrustedEvidenceDemo:
    def test_weakened_visible_test_is_green_but_trusted_test_blocks(self, repo, gate):
        """The headline scenario: candidate tests PASS, trusted base test FAILS -> BLOCK."""
        _base(repo)
        repo.commit({"app/auth.py": AUTH_BROKEN, "tests/test_auth.py": VISIBLE_TEST_WEAKENED})
        res = gate()
        by_name = {c.name: c for c in res.checks}
        assert by_name["candidate-tests"].status.value == "PASS"
        assert by_name["candidate-tests"].source == "head"
        assert by_name["auth-contract"].status.value == "FAIL"
        assert by_name["auth-contract"].source == "base"
        assert res.decision is Decision.FAIL
        assert "trusted_evidence_failed" in codes(res)
        assert res.sections["Trusted evidence"] == "FAIL"
        overlay = res.receipt["trusted_evidence"][0]
        assert overlay["source"] == "base" and overlay["files"] == 3

    def test_legitimate_patch_passes_trusted_evidence(self, repo, gate):
        _base(repo)
        repo.commit(
            {"app/auth.py": AUTH_OK.replace('== "admin"', 'in ("admin",)')},
        )
        res = gate()
        assert res.decision is Decision.PASS, res.receipt["reasons"]
        assert [c.status.value for c in res.checks] == ["PASS", "PASS"]

    def test_candidate_edit_of_trusted_test_is_discarded(self, repo, gate):
        _base(repo)
        repo.commit(
            {
                "app/auth.py": AUTH_BROKEN,
                "trusted_tests/test_auth_contract.py": "def test_ok():\n    assert True\n",
            }
        )
        res = gate()
        assert res.decision is Decision.FAIL
        assert {"trusted_evidence_failed", "trusted_evidence_modified"} <= codes(res)
        ov = res.receipt["trusted_evidence"][0]
        assert "trusted_tests/test_auth_contract.py" in ov["candidate_files_replaced"]

    def test_candidate_deleting_trusted_evidence_does_not_help(self, repo, gate):
        _base(repo)
        repo.commit(
            {"app/auth.py": AUTH_BROKEN},
            delete=("trusted_tests/test_auth_contract.py",),
        )
        res = gate()
        assert res.decision is Decision.FAIL
        assert "trusted_evidence_failed" in codes(res)

    def test_candidate_conftest_inside_trusted_paths_is_removed(self, repo, gate):
        _base(repo)
        hook = (
            "import pytest\n\n@pytest.hookimpl(hookwrapper=True)\n"
            "def pytest_runtest_makereport(item, call):\n"
            "    out = yield\n    rep = out.get_result()\n    rep.outcome = 'passed'\n"
        )
        repo.commit({"app/auth.py": AUTH_BROKEN, "trusted_tests/conftest.py": hook})
        res = gate()
        assert res.decision is Decision.FAIL
        ov = res.receipt["trusted_evidence"][0]
        assert "trusted_tests/conftest.py" in ov["candidate_files_removed"]

    def test_root_conftest_cannot_reach_trusted_run(self, repo, gate):
        """--confcutdir in the trusted command stops a candidate root conftest."""
        _base(repo)
        hook = (
            "import pytest\n\n@pytest.hookimpl(hookwrapper=True)\n"
            "def pytest_runtest_makereport(item, call):\n"
            "    out = yield\n    rep = out.get_result()\n    rep.outcome = 'passed'\n"
        )
        repo.commit({"app/auth.py": AUTH_BROKEN, "conftest.py": hook})
        res = gate()
        assert "trusted_evidence_failed" in codes(res)
        assert res.decision is Decision.FAIL

    def test_symlinked_trusted_dir_cannot_redirect_overlay(self, repo, gate, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "keep.txt").write_text("untouched")
        _base(repo)
        repo.git("rm", "-r", "-q", "trusted_tests")
        (repo.root / "trusted_tests").symlink_to(outside)
        repo.commit({"app/auth.py": AUTH_BROKEN})
        res = gate()
        assert res.decision is Decision.FAIL
        assert "trusted_evidence_failed" in codes(res)
        assert sorted(p.name for p in outside.iterdir()) == ["keep.txt"]
        assert (outside / "keep.txt").read_text() == "untouched"

    def test_trusted_content_comes_from_base_not_head(self, repo, gate):
        """Even when the candidate changes trusted files, the merge-base version runs."""
        _base(repo)
        repo.commit({"trusted_tests/test_auth_contract.py": "def test_x():\n    assert False\n"})
        res = gate()
        # base version passes against unchanged code; the candidate's failing edit is ignored
        assert "trusted_evidence_failed" not in codes(res)
        assert next(c for c in res.checks if c.name == "auth-contract").status.value == "PASS"
        # the edit itself is still reported (and its removed tests block independently)
        assert {"trusted_evidence_modified", "test_function_removed"} <= codes(res)

    def test_trusted_paths_matching_nothing_is_error(self, repo, gate):
        pol = _policy().replace("trusted_tests/**", "missing_dir/**")
        _base(repo, pol)
        repo.commit({"app/auth.py": AUTH_OK + "\n"})
        res = gate()
        assert res.receipt["policy"] is not None
        assert res.decision is Decision.ERROR
        assert any(e.stage == "trusted_evidence" for e in res.errors)


class TestBundles:
    FILES = {
        "test_release.py": b"from app.auth import can_delete\n\ndef test_stranger():\n"
        b"    assert can_delete({'id': 2, 'role': 'u'}, {'owner': 1}) is False\n"
    }

    def _bundle(self, tmp_path: Path) -> tuple[Path, str]:
        path = tmp_path / "bundle.tar"
        path.write_bytes(bundle_from_bytes(self.FILES))
        return path, tree_digest(read_bundle(path))

    def _policy(self, digest: str, bundle: str | None = None) -> str:
        loc = f"    bundle: {bundle}\n" if bundle else ""
        return f"""
version: 1
trusted_evidence:
  - name: release-invariants
    source: bundle
    digest: {digest}
    mount: release_tests
{loc}    command: [{PY!r}, -m, pytest, -q, -p, no:cacheprovider, --confcutdir, release_tests, release_tests]
"""

    def _repo(self, repo, policy):
        repo.commit({"review-gate.yaml": policy, "app/__init__.py": "", "app/auth.py": AUTH_OK})
        repo.git("checkout", "-q", "-b", "agent")

    def test_digest_is_stable_across_dir_and_tar(self, tmp_path):
        tar, digest = self._bundle(tmp_path)
        d = tmp_path / "dir"
        d.mkdir()
        (d / "test_release.py").write_bytes(self.FILES["test_release.py"])
        assert tree_digest(read_bundle(d)) == digest
        assert main(["bundle", "digest", str(tar)]) == 0

    def test_pinned_bundle_blocks_broken_patch(self, repo, gate, tmp_path):
        bundle, digest = self._bundle(tmp_path)
        self._repo(repo, self._policy(digest))
        repo.commit({"app/auth.py": AUTH_BROKEN})
        res = gate(bundles={"release-invariants": str(bundle)})
        assert res.decision is Decision.FAIL
        assert "trusted_evidence_failed" in codes(res)
        assert res.receipt["trusted_evidence"][0]["digest"] == digest

    def test_pinned_bundle_passes_good_patch(self, repo, gate, tmp_path):
        bundle, digest = self._bundle(tmp_path)
        self._repo(repo, self._policy(digest, str(bundle)))
        repo.commit({"app/auth.py": AUTH_OK + "\n# tidy\n"})
        res = gate()
        assert res.decision is Decision.PASS, res.receipt["reasons"]

    def test_wrong_digest_is_error_never_used(self, repo, gate, tmp_path):
        bundle, _ = self._bundle(tmp_path)
        wrong = "sha256:" + "0" * 64
        self._repo(repo, self._policy(wrong))
        repo.commit({"app/auth.py": AUTH_OK + "\n"})
        res = gate(bundles={"release-invariants": str(bundle)})
        assert res.receipt["policy"] is not None
        assert res.decision is Decision.ERROR
        assert any("digest mismatch" in e.message for e in res.errors)
        assert not [c for c in res.checks if c.name == "release-invariants"]

    def test_tampered_bundle_content_is_rejected(self, tmp_path):
        bundle, digest = self._bundle(tmp_path)
        bundle.write_bytes(bundle_from_bytes({"test_release.py": b"def test_x():\n    pass\n"}))
        try:
            load_bundle(bundle, digest)
        except TrustedEvidenceError as exc:
            assert "digest mismatch" in str(exc)
        else:
            raise AssertionError("tampered bundle accepted")

    def test_missing_bundle_is_error(self, repo, gate, tmp_path):
        _, digest = self._bundle(tmp_path)
        self._repo(repo, self._policy(digest))
        repo.commit({"app/auth.py": AUTH_OK + "\n"})
        res = gate()
        assert res.receipt["policy"] is not None
        assert res.decision is Decision.ERROR

    def test_bundle_with_traversal_member_is_rejected(self, tmp_path):
        evil = tmp_path / "evil.tar"
        evil.write_bytes(bundle_from_bytes({"../escape.py": b"x"}))
        try:
            read_bundle(evil)
        except TrustedEvidenceError:
            pass
        else:
            raise AssertionError("traversal accepted")

    def test_patch_touching_bundle_mount_is_reported(self, repo, gate, tmp_path):
        bundle, digest = self._bundle(tmp_path)
        self._repo(repo, self._policy(digest, str(bundle)))
        repo.commit({"release_tests/test_release.py": "def test_stranger():\n    assert True\n"})
        res = gate()
        assert "trusted_evidence_modified" in codes(res)
        f = next(f for f in res.findings if f.code == "trusted_evidence_modified")
        assert f.severity is Severity.REVIEW
