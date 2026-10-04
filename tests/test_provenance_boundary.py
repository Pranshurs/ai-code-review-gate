"""Subject provenance vs execution provenance.

The gate evaluates a target repository (base B, head H). The process running it
may sit inside an unrelated GitHub Actions run (GITHUB_SHA = X). ``subject.ci``
records where the gate ran; it must never change what the gate evaluated, and
X may stand in for H as an evidence revision only when X *is* H or GitHub's
pull_request merge of exactly B and H.
"""

import pytest

from aicrg.model import Decision
from aicrg.receipt.receipt import write_receipt
from aicrg.receipt.verify import verify_receipt
from tests.test_security_review_regressions import EXT_POLICY, _sarif

UNRELATED_X = "e" * 40  # a commit of the runner's own repository, absent from the target


def _actions(monkeypatch, sha, repository="other-org/runner", ref="refs/heads/release"):
    for k, v in {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": repository,
        "GITHUB_SHA": sha,
        "GITHUB_REF": ref,
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_WORKFLOW_REF": f"{repository}/.github/workflows/x.yml@{ref}",
        "GITHUB_RUN_ID": "99",
        "GITHUB_RUN_ATTEMPT": "1",
    }.items():
        monkeypatch.setenv(k, v)


def _setup(repo, policy="version: 1\n"):
    base = repo.commit({"review-gate.yaml": policy, "a.py": "x = 1\n"})
    repo.git("checkout", "-q", "-b", "agent")
    head = repo.commit({"a.py": "x = 2\n"})
    return base, head


def _subject_without_ci(receipt):
    return {k: v for k, v in receipt["subject"].items() if k != "ci"}


@pytest.mark.parametrize(
    "sha",
    [UNRELATED_X, "", "--all", "not-a-sha", "E" * 40],
    ids=["unrelated-repo", "empty", "option-like", "garbage", "uppercase"],
)
def test_ambient_ci_cannot_alter_the_subject(repo, gate, monkeypatch, sha):
    _, head = _setup(repo)
    plain = gate()
    _actions(monkeypatch, sha)
    under_ci = gate()
    s = under_ci.receipt["subject"]
    assert s["head"] == head != sha
    assert _subject_without_ci(under_ci.receipt) == _subject_without_ci(plain.receipt)
    assert under_ci.decision is plain.decision
    assert s["ci"]["sha"] == sha and s["ci"]["repository"] == "other-org/runner"
    assert s["ci"]["relation"] == "unresolved"


def test_ci_commit_in_target_but_unrelated_to_head(repo, gate, monkeypatch):
    base, head = _setup(repo)
    _actions(monkeypatch, base)  # e.g. a workflow_dispatch on main checking out the PR
    s = gate().receipt["subject"]
    assert s["head"] == head and s["base"] == base
    assert s["ci"]["sha"] == base and s["ci"]["relation"] == "unrelated"


def test_ci_relation_head_and_merge(repo, gate, monkeypatch):
    base, head = _setup(repo)
    _actions(monkeypatch, head)
    assert gate().receipt["subject"]["ci"]["relation"] == "head"
    merge = repo.git("commit-tree", "HEAD^{tree}", "-p", base, "-p", head, "-m", "m")
    _actions(monkeypatch, merge)
    s = gate().receipt["subject"]
    assert s["head"] == head and s["ci"]["relation"] == "merge_of_head"


def test_merge_with_other_base_is_not_a_merge_of_head(repo, gate, monkeypatch):
    base, head = _setup(repo)
    other = repo.git("commit-tree", "main^{tree}", "-p", base, "-m", "elsewhere")
    reversed_parents = repo.git("commit-tree", "HEAD^{tree}", "-p", head, "-p", base, "-m", "m")
    wrong_base = repo.git("commit-tree", "HEAD^{tree}", "-p", other, "-p", head, "-m", "m")
    for sha in (reversed_parents, wrong_base):
        _actions(monkeypatch, sha)
        assert gate().receipt["subject"]["ci"]["relation"] == "unrelated", sha


# ----------------------------------------------------------------------------- evidence binding


def test_report_for_unrelated_ci_commit_is_not_evidence_for_head(repo, gate, monkeypatch, tmp_path):
    """Reproduced product bug: a clean SARIF report of the runner's own commit X was
    accepted as external evidence about the target head H (decision PASS)."""
    _setup(repo, EXT_POLICY)
    _actions(monkeypatch, UNRELATED_X)
    rep = tmp_path / "x.sarif"
    rep.write_text(_sarif(UNRELATED_X))
    assert gate(external_evidence={"codeql": str(rep)}).decision is Decision.ERROR


def test_report_for_unrelated_commit_in_target_is_refused(repo, gate, monkeypatch, tmp_path):
    base, _ = _setup(repo, EXT_POLICY)
    _actions(monkeypatch, base)
    rep = tmp_path / "b.sarif"
    rep.write_text(_sarif(base))
    assert gate(external_evidence={"codeql": str(rep)}).decision is Decision.ERROR


def test_report_for_pull_request_merge_commit_is_evidence(repo, gate, monkeypatch, tmp_path):
    base, head = _setup(repo, EXT_POLICY)
    merge = repo.git("commit-tree", "HEAD^{tree}", "-p", base, "-p", head, "-m", "m")
    _actions(monkeypatch, merge)
    rep = tmp_path / "m.sarif"
    rep.write_text(_sarif(merge))
    assert gate(external_evidence={"codeql": str(rep)}).decision is Decision.PASS


def test_report_for_head_is_evidence_whatever_the_ci_context(repo, gate, monkeypatch, tmp_path):
    _, head = _setup(repo, EXT_POLICY)
    _actions(monkeypatch, UNRELATED_X)
    rep = tmp_path / "h.sarif"
    rep.write_text(_sarif(head))
    assert gate(external_evidence={"codeql": str(rep)}).decision is Decision.PASS


# ----------------------------------------------------------------------------- verification


def test_verification_binds_the_reviewed_head_not_the_ci_commit(repo, gate, monkeypatch, tmp_path):
    _, head = _setup(repo)
    _actions(monkeypatch, UNRELATED_X)
    path = write_receipt(gate().receipt, tmp_path / "r")
    assert verify_receipt(path, repo.root, base="main").ok
    # Moving the reviewed head makes the receipt stale, whatever the CI context says.
    repo.commit({"a.py": "x = 3\n"})
    v = verify_receipt(path, repo.root, base="main")
    assert not v.ok and any("STALE" in p for p in v.problems), v.problems
    assert head not in repo.git("rev-parse", "HEAD")
