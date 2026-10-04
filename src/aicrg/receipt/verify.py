"""Check that a receipt still authorises the code that is about to be merged.

A receipt authorises exactly one (head commit, patch, policy, gate version).
If any of those moved, the receipt is stale and must be rejected rather than
silently reused.

Three properties are reported separately:

INTEGRITY     the receipt matches its own ``receipt_digest``.
AUTHENTICITY  a trusted identity signed the receipt (see ``receipt.attest``).
BINDING       the receipt is for this repository, head, patch, base and policy.

Attestation is *required* when the base contract says so
(``attestation.required``, read from ``--base``) or the verifier passes
``--require-attestation``. A required but missing/invalid attestation rejects
the receipt; it never degrades to "integrity only".
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from aicrg import __version__
from aicrg.git.diff import patch_digest
from aicrg.git.repo import GitError, Repo
from aicrg.policy.contract import AttestationPolicy, PolicyError
from aicrg.policy.loader import load_policy
from aicrg.receipt.attest import (
    Authenticity,
    GithubIdentity,
    github_verify,
    ssh_verify,
)
from aicrg.receipt.receipt import SUPPORTED_SCHEMAS, compute_digest, load_receipt


@dataclass(slots=True)
class AttestationOptions:
    require: bool = False
    method: str | None = None  # github | ssh; default from the base contract
    signature: Path | None = None  # ssh signature file
    allowed_signers: Path | None = None  # ssh, operator-supplied (else from base contract)
    identity: str | None = None  # ssh principal
    repository: str | None = None  # github owner/repo
    signer_workflow: str | None = None
    signer_ref: str | None = None
    bundle: Path | None = None  # github: offline attestation bundle
    base_signers: bytes | None = None  # ssh allowed_signers read from the base commit


@dataclass(slots=True)
class Verification:
    ok: bool
    problems: list[str] = field(default_factory=list)
    receipt: dict[str, Any] | None = None
    integrity: str = "UNKNOWN"
    authenticity: Authenticity = field(default_factory=lambda: Authenticity("UNATTESTED"))


def verify_receipt(
    path: Path,
    cwd: Path,
    head: str = "HEAD",
    base: str | None = None,
    require_pass: bool = True,
    *,
    attestation: AttestationOptions | None = None,
) -> Verification:
    att = attestation or AttestationOptions()
    problems: list[str] = []
    try:
        raw = path.read_bytes()
        r = load_receipt(path)
    except (OSError, ValueError) as exc:
        return Verification(False, [f"cannot read receipt: {exc}"], integrity="FAILED")

    if r.get("schema") not in SUPPORTED_SCHEMAS:
        return Verification(
            False, [f"unsupported receipt schema {r.get('schema')!r}"], r, integrity="FAILED"
        )
    integrity = "VERIFIED"
    if r.get("receipt_digest") != compute_digest(r):
        integrity = "FAILED"
        problems.append("receipt_digest mismatch: receipt was modified after it was sealed")
    if require_pass and r.get("decision") != "PASS":
        problems.append(f"receipt decision is {r.get('decision')}, not PASS")
    gate_version = (r.get("gate") or {}).get("version")
    if gate_version != __version__:
        problems.append(f"receipt produced by gate {gate_version}, verifier is {__version__}")

    subject = r.get("subject") or {}
    policy_att = AttestationPolicy()
    repo: Repo | None = None
    try:
        repo = Repo.discover(cwd)
        current_head = repo.resolve_commit(head)
        if subject.get("head") != current_head:
            problems.append(
                f"STALE: receipt is for head {str(subject.get('head'))[:12]}, "
                f"current {head} is {current_head[:12]}"
            )
        ident = repo.identity()
        rec_ident = subject.get("repository") or {}
        if rec_ident.get("root_commits") != ident.get("root_commits"):
            problems.append("receipt was produced for a different repository")
        merge_base = subject.get("merge_base")
        if (
            isinstance(merge_base, str)
            and subject.get("head") == current_head
            and patch_digest(repo, merge_base, current_head) != subject.get("patch_digest")
        ):
            problems.append("patch digest mismatch for the evaluated range")
        if base is not None:
            # The receipt evaluated merge-base..head with the base tip at that time. If the
            # target branch moved, the code that will actually be merged was never evaluated.
            cur_base = repo.resolve_commit(base)
            if cur_base != subject.get("base"):
                problems.append(
                    f"STALE: {base} has moved to {cur_base[:12]} since evaluation against "
                    f"{str(subject.get('base'))[:12]}; re-run the gate on the updated branch"
                )
            policy_rec = r.get("policy") or {}
            source = str(policy_rec.get("source", ""))
            if source.startswith("base:") or source == "builtin-default":
                pol = load_policy(
                    repo,
                    cur_base,
                    source.removeprefix("base:") if source.startswith("base:") else None,
                    "base",
                )
                if pol.contract.digest() != policy_rec.get("contract_digest"):
                    problems.append("policy on the base branch changed since evaluation")
                policy_att = pol.contract.attestation
                if policy_att.method == "ssh" and policy_att.allowed_signers:
                    blob = repo.read_blob(cur_base, policy_att.allowed_signers)
                    if blob is None:
                        problems.append(
                            f"allowed_signers {policy_att.allowed_signers} missing at base"
                        )
                    else:
                        att = replace(att, base_signers=blob)
        _check_ci_commit(repo, subject, problems)
    except (GitError, PolicyError) as exc:
        problems.append(f"cannot verify against repository: {exc}")

    required = att.require or policy_att.required
    auth = _authenticate(path, raw, r, att, policy_att)
    if required and auth.status != "VERIFIED":
        problems.append(
            f"attestation required but authenticity is {auth.status}"
            + (f": {'; '.join(auth.problems)}" if auth.problems else "")
        )
    elif auth.status == "FAILED":
        problems.append("attestation present but invalid: " + "; ".join(auth.problems))
    return Verification(not problems, problems, r, integrity, auth)


def _check_ci_commit(repo: Repo, subject: dict[str, Any], problems: list[str]) -> None:
    """If the gate ran on a CI merge commit, that commit must be built from the head."""
    ci = subject.get("ci") or {}
    sha, head = ci.get("sha"), subject.get("head")
    if not sha or sha == head:
        return
    try:
        parents = repo.git("rev-list", "--parents", "-n", "1", sha).decode().split()[1:]
    except GitError:
        return  # merge ref not fetched locally; the signed receipt's own claim stands
    if head not in parents:
        problems.append(
            f"receipt's CI commit {sha[:12]} is not a merge built from head {str(head)[:12]}"
        )


def _authenticate(
    path: Path,
    raw: bytes,
    r: dict[str, Any],
    att: AttestationOptions,
    pol: AttestationPolicy,
) -> Authenticity:
    method = att.method or (pol.method if pol.required else None)
    if method is None:
        if any(
            x is not None
            for x in (att.signature, att.allowed_signers, att.identity, att.base_signers)
        ):
            method = "ssh"
        elif any(x is not None for x in (att.bundle, att.repository, att.signer_workflow)):
            method = "github"
        else:
            return Authenticity("UNATTESTED")
    if method == "ssh":
        identity = att.identity or pol.identity
        # Signers pinned by the base contract win over an operator-supplied file.
        signers = att.base_signers
        if signers is None and att.allowed_signers is not None:
            try:
                signers = att.allowed_signers.read_bytes()
            except OSError as exc:
                return Authenticity("FAILED", "ssh", identity, [f"allowed_signers: {exc}"])
        if signers is None or not identity:
            return Authenticity(
                "FAILED", "ssh", identity, ["ssh verification needs allowed_signers and identity"]
            )
        sig = att.signature or path.with_name(path.name + ".sig")
        return ssh_verify(raw, sig if sig.exists() else None, signers, identity)
    if method == "github":
        repo_name = att.repository or pol.repository
        if not repo_name:
            return Authenticity("FAILED", "github", None, ["github verification needs --repo"])
        ident = GithubIdentity(
            repo_name,
            att.signer_workflow or pol.signer_workflow,
            att.signer_ref or pol.signer_ref,
        )
        return github_verify(path, r, ident, att.bundle)
    return Authenticity("FAILED", method, None, [f"unknown attestation method {method!r}"])
