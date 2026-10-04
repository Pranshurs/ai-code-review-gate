"""Receipt authenticity: integrity is not authenticity."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from aicrg.cli import main
from aicrg.receipt.attest import (
    PREDICATE_TYPE,
    STATEMENT_TYPE,
    GithubIdentity,
    github_verify,
    statement,
)
from aicrg.receipt.receipt import seal, write_receipt
from aicrg.receipt.verify import AttestationOptions, verify_receipt
from tests.conftest import POLICY_NO_CHECKS

needs_ssh = pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="ssh-keygen missing")


def _pass_receipt(repo, gate, tmp_path, policy=POLICY_NO_CHECKS):
    repo.commit({"review-gate.yaml": policy, "a.py": "x = 1\n"})
    repo.git("checkout", "-q", "-b", "agent")
    repo.commit({"a.py": "x = 2\n"})
    res = gate()
    assert res.decision.value == "PASS", res.receipt["reasons"]
    return write_receipt(res.receipt, tmp_path / "receipts"), res


def _keypair(tmp_path: Path, name: str = "gate") -> tuple[Path, Path]:
    key = tmp_path / name
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(key)], check=True
    )
    signers = tmp_path / f"{name}.allowed"
    signers.write_text(f"gate@aicrg {(tmp_path / (name + '.pub')).read_text()}")
    return key, signers


def _reseal_with(path: Path, **changes):
    r = json.loads(path.read_text())
    r.update(changes)
    path.write_text(json.dumps(seal(r), indent=2, sort_keys=True) + "\n")


@needs_ssh
class TestSsh:
    def test_signed_receipt_is_authentic(self, repo, gate, tmp_path):
        path, _ = _pass_receipt(repo, gate, tmp_path)
        key, signers = _keypair(tmp_path)
        assert main(["receipt", "sign", str(path), "--key", str(key)]) == 0
        opts = AttestationOptions(require=True, allowed_signers=signers, identity="gate@aicrg")
        v = verify_receipt(path, repo.root, attestation=opts)
        assert v.ok, v.problems
        assert v.integrity == "VERIFIED" and v.authenticity.status == "VERIFIED"

    def test_unsigned_receipt_rejected_when_attestation_required(self, repo, gate, tmp_path):
        path, _ = _pass_receipt(repo, gate, tmp_path)
        _, signers = _keypair(tmp_path)
        opts = AttestationOptions(require=True, allowed_signers=signers, identity="gate@aicrg")
        v = verify_receipt(path, repo.root, attestation=opts)
        assert not v.ok
        assert v.integrity == "VERIFIED" and v.authenticity.status == "UNATTESTED"

    def test_unsigned_receipt_reported_unattested_when_optional(self, repo, gate, tmp_path):
        path, _ = _pass_receipt(repo, gate, tmp_path)
        v = verify_receipt(path, repo.root)
        assert v.ok and v.authenticity.status == "UNATTESTED"

    def test_edited_and_resealed_receipt_fails_authenticity(self, repo, gate, tmp_path):
        """An attacker who can recompute receipt_digest still cannot forge the signature."""
        path, _ = _pass_receipt(repo, gate, tmp_path)
        key, signers = _keypair(tmp_path)
        main(["receipt", "sign", str(path), "--key", str(key)])
        _reseal_with(path, reasons=["looks fine to me"])
        opts = AttestationOptions(require=True, allowed_signers=signers, identity="gate@aicrg")
        v = verify_receipt(path, repo.root, attestation=opts)
        assert v.integrity == "VERIFIED"  # the digest was recomputed...
        assert v.authenticity.status == "FAILED" and not v.ok  # ...but the signature breaks

    def test_signature_by_untrusted_key_fails(self, repo, gate, tmp_path):
        path, _ = _pass_receipt(repo, gate, tmp_path)
        _, signers = _keypair(tmp_path, "gate")
        other, _ = _keypair(tmp_path, "attacker")
        main(["receipt", "sign", str(path), "--key", str(other)])
        opts = AttestationOptions(require=True, allowed_signers=signers, identity="gate@aicrg")
        assert not verify_receipt(path, repo.root, attestation=opts).ok

    def test_base_contract_requires_attestation_and_pins_signers(self, repo, gate, tmp_path):
        key, signers = _keypair(tmp_path)
        attacker, attacker_signers = _keypair(tmp_path, "attacker")
        policy = (
            "version: 1\nattestation:\n  required: true\n  method: ssh\n"
            "  allowed_signers: .aicrg/allowed_signers\n  identity: gate@aicrg\n"
        )
        repo.commit(
            {
                "review-gate.yaml": policy,
                ".aicrg/allowed_signers": signers.read_text(),
                "a.py": "x=1\n",
            }
        )
        repo.git("checkout", "-q", "-b", "agent")
        # The candidate swaps in its own key; verification must still use the base copy.
        repo.commit({"a.py": "x = 2\n", ".aicrg/allowed_signers": attacker_signers.read_text()})
        res = gate()
        path = write_receipt(res.receipt, tmp_path / "r")
        assert (
            verify_receipt(path, repo.root, base="main", require_pass=False).authenticity.status
            == "UNATTESTED"
        )
        assert not verify_receipt(path, repo.root, base="main", require_pass=False).ok
        assert main(["receipt", "sign", str(path), "--key", str(attacker)]) == 0
        v = verify_receipt(path, repo.root, base="main", require_pass=False)
        assert v.authenticity.status == "FAILED" and not v.ok
        assert main(["receipt", "sign", str(path), "--key", str(key)]) == 0
        v = verify_receipt(path, repo.root, base="main", require_pass=False)
        assert v.authenticity.status == "VERIFIED" and v.ok, v.problems

    def test_forged_policy_source_cannot_skip_required_attestation(self, repo, gate, tmp_path):
        """F1: the receipt's own policy.source must not decide which contract applies."""
        _, signers = _keypair(tmp_path)
        policy = (
            "version: 1\nattestation:\n  required: true\n  method: ssh\n"
            "  allowed_signers: .aicrg/allowed_signers\n  identity: gate@aicrg\n"
        )
        repo.commit(
            {
                "review-gate.yaml": policy,
                ".aicrg/allowed_signers": signers.read_text(),
                "a.py": "x=1\n",
            }
        )
        repo.git("checkout", "-q", "-b", "agent")
        repo.commit({"a.py": "x = 2\n"})
        path = write_receipt(gate().receipt, tmp_path / "r")
        _reseal_with(path, policy={**json.loads(path.read_text())["policy"], "source": "file:x"})
        v = verify_receipt(path, repo.root, base="main")
        assert not v.ok
        assert any("evaluated under policy" in p for p in v.problems)
        assert any("attestation required" in p for p in v.problems)

    def test_cli_reports_integrity_and_authenticity(
        self, repo, gate, tmp_path, capsys, monkeypatch
    ):
        path, _ = _pass_receipt(repo, gate, tmp_path)
        monkeypatch.chdir(repo.root)
        assert main(["verify-receipt", str(path), "--base", "main"]) == 0
        out = capsys.readouterr().out
        assert "INTEGRITY: VERIFIED" in out and "AUTHENTICITY: UNATTESTED" in out
        assert main(["verify-receipt", str(path), "--base", "main", "--require-attestation"]) == 5


# ----------------------------------------------------------------------------- github


def _cert(receipt, **over):
    c = {
        "sourceRepositoryURI": "https://github.com/acme/app",
        "sourceRepositoryDigest": receipt["subject"]["head"],
        "sourceRepositoryRef": "refs/heads/main",
        "buildSignerURI": "https://github.com/acme/app/.github/workflows/gate.yml@refs/heads/main",
        "runInvocationURI": "https://github.com/acme/app/actions/runs/1/attempts/1",
    }
    c.update(over)
    return [{"verificationResult": {"signature": {"certificate": c}}}]


def _runner(payload, rc=0, err=b""):
    def run(argv, stdin):
        return subprocess.CompletedProcess(argv, rc, json.dumps(payload).encode(), err)

    return run


IDENT = GithubIdentity("acme/app", "acme/app/.github/workflows/gate.yml", "refs/heads/main")


class TestGithub:
    def _receipt(self, repo, gate, tmp_path):
        path, res = _pass_receipt(repo, gate, tmp_path)
        return path, res.receipt

    def test_matching_attestation_verifies(self, repo, gate, tmp_path):
        path, r = self._receipt(repo, gate, tmp_path)
        a = github_verify(path, r, IDENT, runner=_runner(_cert(r)))
        assert a.status == "VERIFIED", a.problems

    def test_attestation_for_another_commit_fails(self, repo, gate, tmp_path):
        path, r = self._receipt(repo, gate, tmp_path)
        a = github_verify(path, r, IDENT, runner=_runner(_cert(r, sourceRepositoryDigest="f" * 40)))
        assert a.status == "FAILED" and "commit" in a.problems[0]

    def test_pr_ref_signer_does_not_satisfy_main_pin(self, repo, gate, tmp_path):
        path, r = self._receipt(repo, gate, tmp_path)
        pr = "https://github.com/acme/app/.github/workflows/gate.yml@refs/pull/7/merge"
        a = github_verify(path, r, IDENT, runner=_runner(_cert(r, buildSignerURI=pr)))
        assert a.status == "FAILED"

    def test_other_repository_fails(self, repo, gate, tmp_path):
        path, r = self._receipt(repo, gate, tmp_path)
        a = github_verify(
            path,
            r,
            IDENT,
            runner=_runner(_cert(r, sourceRepositoryURI="https://github.com/evil/app")),
        )
        assert a.status == "FAILED"

    def test_gh_failure_is_failed_not_verified(self, repo, gate, tmp_path):
        path, r = self._receipt(repo, gate, tmp_path)
        a = github_verify(path, r, IDENT, runner=_runner([], rc=1, err=b"signature invalid"))
        assert a.status == "FAILED"
        a = github_verify(path, r, IDENT, runner=_runner([], rc=1, err=b"no attestations found"))
        assert a.status == "UNATTESTED"

    def test_ci_merge_commit_is_the_signed_commit(self, repo, gate, tmp_path):
        path, r = self._receipt(repo, gate, tmp_path)
        r["subject"]["ci"] = {"sha": "a" * 40}
        assert github_verify(path, r, IDENT, runner=_runner(_cert(r))).status == "FAILED"
        assert (
            github_verify(
                path, r, IDENT, runner=_runner(_cert(r, sourceRepositoryDigest="a" * 40))
            ).status
            == "VERIFIED"
        )

    def test_end_to_end_with_fake_gh_cli(self, repo, gate, tmp_path, monkeypatch, capsys):
        path, r = self._receipt(repo, gate, tmp_path)
        bindir = tmp_path / "bin"
        bindir.mkdir()
        out = tmp_path / "gh.json"
        out.write_text(json.dumps(_cert(r)))
        gh = bindir / "gh"
        gh.write_text(
            f"#!{sys.executable}\nimport sys\nsys.stdout.write(open({str(out)!r}).read())\n"
        )
        gh.chmod(0o755)
        monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
        monkeypatch.chdir(repo.root)
        args = [
            "verify-receipt",
            str(path),
            "--base",
            "main",
            "--require-attestation",
            "--attestation",
            "github",
            "--repo",
            "acme/app",
            "--signer-workflow",
            "acme/app/.github/workflows/gate.yml",
        ]
        assert main(args) == 0
        assert "AUTHENTICITY: VERIFIED (github:" in capsys.readouterr().out
        out.write_text(json.dumps(_cert(r, sourceRepositoryDigest="0" * 40)))
        assert main(args) == 5


def test_statement_maps_receipt_to_in_toto(repo, gate, tmp_path):
    _, res = _pass_receipt(repo, gate, tmp_path)
    st = statement(res.receipt)
    assert st["_type"] == STATEMENT_TYPE and st["predicateType"] == PREDICATE_TYPE
    assert st["subject"][0]["digest"] == {"gitCommit": res.receipt["subject"]["head"]}
    assert st["predicate"] == res.receipt


def test_github_contract_requires_pinned_signer():
    from aicrg.policy.contract import PolicyError, parse_contract

    with pytest.raises(PolicyError):
        parse_contract("version: 1\nattestation:\n  required: true\n  repository: acme/app\n")


# ----------------------------------------------------------------------------- CI provenance
# Under GitHub Actions the gate records where it ran; an attestation then has to
# sign that CI commit (for pull_request: the merge commit), not merely the head.


def _actions_env(monkeypatch, sha):
    for k, v in {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": "acme/app",
        "GITHUB_SHA": sha,
        "GITHUB_REF": "refs/pull/7/merge",
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_WORKFLOW_REF": "acme/app/.github/workflows/gate.yml@refs/heads/main",
        "GITHUB_RUN_ID": "1",
        "GITHUB_RUN_ATTEMPT": "1",
    }.items():
        monkeypatch.setenv(k, v)


def _merge_commit(repo):
    """A pull_request-style merge of HEAD into main, without moving HEAD."""
    return repo.git("commit-tree", "HEAD^{tree}", "-p", "main", "-p", "HEAD", "-m", "merge")


class TestCiProvenance:
    def _setup(self, repo):
        repo.commit({"review-gate.yaml": POLICY_NO_CHECKS, "a.py": "x = 1\n"})
        repo.git("checkout", "-q", "-b", "agent")
        return repo.commit({"a.py": "x = 2\n"})

    def test_no_ci_context_outside_actions(self, repo, gate):
        self._setup(repo)
        assert "ci" not in gate().receipt["subject"]

    def test_ci_context_is_recorded_under_actions(self, repo, gate, monkeypatch):
        self._setup(repo)
        merge = _merge_commit(repo)
        _actions_env(monkeypatch, merge)
        ci = gate().receipt["subject"]["ci"]
        assert ci["sha"] == merge and ci["event"] == "pull_request"
        assert ci["provider"] == "github-actions" and ci["repository"] == "acme/app"

    def test_attestation_must_sign_the_ci_commit(self, repo, gate, tmp_path, monkeypatch):
        head = self._setup(repo)
        merge = _merge_commit(repo)
        _actions_env(monkeypatch, merge)
        res = gate()
        path = write_receipt(res.receipt, tmp_path / "receipts")
        r = res.receipt
        ok = github_verify(path, r, IDENT, runner=_runner(_cert(r, sourceRepositoryDigest=merge)))
        assert ok.status == "VERIFIED", ok.problems
        # An attestation over the head alone was not produced by this CI run.
        bad = github_verify(path, r, IDENT, runner=_runner(_cert(r, sourceRepositoryDigest=head)))
        assert bad.status == "FAILED" and "commit" in bad.problems[0]

    def test_ci_merge_commit_built_from_head_verifies(self, repo, gate, tmp_path, monkeypatch):
        self._setup(repo)
        _actions_env(monkeypatch, _merge_commit(repo))
        path = write_receipt(gate().receipt, tmp_path / "receipts")
        v = verify_receipt(path, repo.root, base="main")
        assert v.ok, v.problems

    def test_ci_commit_not_built_from_head_is_rejected(self, repo, gate, tmp_path, monkeypatch):
        self._setup(repo)
        unrelated = repo.git("commit-tree", "main^{tree}", "-p", "main", "-m", "elsewhere")
        _actions_env(monkeypatch, unrelated)
        path = write_receipt(gate().receipt, tmp_path / "receipts")
        v = verify_receipt(path, repo.root, base="main")
        assert not v.ok
        assert any("not a merge built from head" in p for p in v.problems), v.problems
