import pytest

from aicrg.git.repo import Repo
from aicrg.globmatch import GlobError, match
from aicrg.policy.contract import (
    FORBIDDEN_CHANGE_CLASSES,
    PolicyError,
    ReviewContract,
    parse_contract,
)
from aicrg.policy.loader import load_policy


class TestGlob:
    @pytest.mark.parametrize(
        ("path", "pattern", "expected"),
        [
            ("src/a.py", "src/*", True),
            ("src/a/b.py", "src/*", False),  # * must not cross /
            ("src/a/b.py", "src/**", True),
            ("src/a/b.py", "src/**/*.py", True),
            ("src/b.py", "src/**/*.py", True),  # ** matches zero dirs
            ("deep/x/uv.lock", "*.lock", True),  # basename pattern at any depth
            (".github/workflows/ci.yml", ".github/**", True),
            ("github/workflows/ci.yml", ".github/**", False),
            ("srcx/a.py", "src/**", False),
        ],
    )
    def test_semantics(self, path, pattern, expected):
        assert match(path, pattern) is expected

    @pytest.mark.parametrize("bad", ["", "/abs/**", "a\\b", "src/[ab].py", "{a,b}"])
    def test_rejects_ambiguous_patterns(self, bad):
        with pytest.raises(GlobError):
            match("x", bad)


class TestContractParsing:
    def test_full_contract(self):
        c = parse_contract(
            """
version: 1
allowed_paths: [src/**, tests/**]
protected_paths: [.github/**]
required_checks:
  - pytest
  - name: lint
    command: ruff check .
    timeout_seconds: 60
forbidden_changes: [test_deletion]
dependency_policy:
  allow_new_runtime_dependencies: false
  allowed_new_dependencies: [Requests]
minimum_test_integrity:
  forbid_new_unconditional_skips: false
review_required_surfaces: [ci]
"""
        )
        assert [ch.name for ch in c.required_checks] == ["pytest", "lint"]
        assert c.required_checks[1].argv == ("ruff", "check", ".")
        assert c.forbids("test_deletion")
        assert not c.forbids("secret_introduction")
        assert c.dependency_policy.allowed_new_dependencies == ("requests",)
        assert c.minimum_test_integrity.forbid_new_unconditional_skips is False
        assert c.minimum_test_integrity.forbid_assertion_weakening is True

    def test_defaults_are_strict(self):
        c = parse_contract("version: 1\n")
        assert c.forbidden_changes == frozenset(FORBIDDEN_CHANGE_CLASSES)
        assert c.dependency_policy.allow_new_runtime_dependencies is False
        assert c.minimum_test_integrity.forbid_removed_security_assertions is True

    @pytest.mark.parametrize(
        "text",
        [
            "",  # not a mapping
            "- a\n",
            "version: 2\n",
            "version: true\n",
            "allowed_paths: [src/**]\n",  # missing version
            "version: 1\nunknown_key: 1\n",
            "version: 1\nforbidden_changes: [test_deletion, typo_class]\n",
            "version: 1\nforbiden_changes: [test_deletion]\n",
            "version: 1\nallowed_paths: []\n",
            "version: 1\nallowed_paths: [/etc/**]\n",
            "version: 1\nrequired_checks: [{name: t}]\n",
            "version: 1\nrequired_checks: [{name: t, command: ''}]\n",
            "version: 1\nrequired_checks: [pytest, pytest]\n",
            "version: 1\nrequired_checks: [{name: t, command: x, timeout_seconds: 0}]\n",
            "version: 1\ndependency_policy: {allow_new_runtime_dependencies: 'no'}\n",
            "version: 1\ndependency_policy: {allow_new_runtime_dependencies: 1}\n",
            "version: 1\nminimum_test_integrity: {forbid_new_unconditional_skips: null}\n",
            "version: 1\nreview_required_surfaces: [everything]\n",
            "version: 1\nversion: 1\n",  # duplicate key
            "version: 1\ndependency_policy:\n  max_new_dependencies: 1\n  max_new_dependencies: 99\n",
            "version: 1\nrequired_checks: 'pytest'\n",
            "version: 1\n: :\n  - [",
        ],
    )
    def test_malformed_policy_fails_closed(self, text):
        with pytest.raises(PolicyError):
            parse_contract(text)

    def test_digest_is_stable_and_sensitive(self):
        a = parse_contract("version: 1\nprotected_paths: [a/**]\n")
        b = parse_contract("protected_paths: [a/**]\nversion: 1\n")
        c = parse_contract("version: 1\nprotected_paths: [b/**]\n")
        assert a.digest() == b.digest()
        assert a.digest() != c.digest()
        assert ReviewContract().digest() == parse_contract("version: 1\n").digest()


class TestPolicySource:
    def test_policy_is_read_from_base_not_head(self, repo):
        base = repo.commit({"review-gate.yaml": "version: 1\nprotected_paths: [secret/**]\n"})
        repo.commit({"review-gate.yaml": "version: 1\n"})
        pol = load_policy(Repo(repo.root), base, None)
        assert pol.source == "base:review-gate.yaml"
        assert pol.contract.protected_paths == ("secret/**",)

    def test_explicit_policy_missing_at_base_is_an_error(self, repo):
        base = repo.commit({"README.md": "x"})
        repo.commit({"review-gate.yaml": "version: 1\n"})
        with pytest.raises(PolicyError, match="does not exist at base"):
            load_policy(Repo(repo.root), base, "review-gate.yaml")

    def test_no_policy_uses_strict_builtin_default(self, repo):
        base = repo.commit({"README.md": "x"})
        pol = load_policy(Repo(repo.root), base, None)
        assert pol.source == "builtin-default"
        assert pol.contract == ReviewContract()

    def test_dotfile_policy_name_is_not_mangled(self, repo):
        base = repo.commit({".aicrg.yaml": "version: 1\nprotected_paths: [x/**]\n"})
        pol = load_policy(Repo(repo.root), base, None)
        assert pol.source == "base:.aicrg.yaml"

    def test_path_escape_rejected(self, repo):
        base = repo.commit({"README.md": "x"})
        with pytest.raises(PolicyError):
            load_policy(Repo(repo.root), base, "../outside.yaml")
