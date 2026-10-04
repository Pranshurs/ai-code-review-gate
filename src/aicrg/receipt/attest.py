"""Receipt authenticity: who produced this receipt?

``receipt_digest`` gives *integrity* (the receipt matches its own digest) but
anyone who can write the file can recompute it. Authenticity needs a signature
by an identity the verifier trusts. AICRG does no cryptography of its own; it
drives standard tools and checks the identities they report:

``github``  GitHub artifact attestations (Sigstore keyless signing, Fulcio
            certificate bound to the workflow run, Rekor transparency log).
            Produced in CI with ``actions/attest-build-provenance`` on
            ``review-receipt.json``; verified with ``gh attestation verify``.
            AICRG then checks the certificate claims itself:
              * source repository is the expected one;
              * signer workflow **and ref** equal the pinned identity (a
                ``pull_request`` run is signed by ``refs/pull/N/merge``, a
                workflow the PR can edit, so it must not satisfy a pin on
                ``refs/heads/main``);
              * the signed source commit is the commit the receipt says the
                gate ran on (``subject.ci.sha``, else ``subject.head``).
``ssh``     ``ssh-keygen -Y sign`` / ``-Y verify`` with an ``allowed_signers``
            file read from the **base** commit (the patch cannot add a key).
            Useful offline and for self-hosted gates.

The verifier reports integrity and authenticity separately:

    INTEGRITY: VERIFIED       AUTHENTICITY: UNATTESTED
    INTEGRITY: VERIFIED       AUTHENTICITY: VERIFIED (github: owner/repo ...)

``statement()`` wraps a receipt as an in-toto Statement v1 so it can be
attested as a custom predicate later. This is a mapping, not a claim of SLSA
conformance.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aicrg.receipt.receipt import canonical_bytes

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://github.com/Pranshurs/ai-code-review-gate/receipt/v2"
SSH_NAMESPACE = "aicrg-receipt"


@dataclass(slots=True)
class Authenticity:
    status: str  # VERIFIED | UNATTESTED | FAILED
    method: str | None = None
    identity: str | None = None
    problems: list[str] = field(default_factory=list)
    claims: dict[str, Any] = field(default_factory=dict)

    def line(self) -> str:
        if self.status == "VERIFIED":
            return f"AUTHENTICITY: VERIFIED ({self.method}: {self.identity})"
        return f"AUTHENTICITY: {self.status}"


def statement(receipt: dict[str, Any]) -> dict[str, Any]:
    subj = receipt.get("subject") or {}
    repo = (subj.get("repository") or {}).get("remote") or "unknown"
    head = subj.get("head")
    digest = hashlib.sha256(canonical_bytes(receipt)).hexdigest()
    return {
        "_type": STATEMENT_TYPE,
        "subject": [
            {"name": f"git+{repo}@{head}", "digest": {"gitCommit": head}},
            {"name": "aicrg-receipt", "digest": {"sha256": digest}},
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": receipt,
    }


# --------------------------------------------------------------------------- ssh


Runner = Callable[[list[str], bytes | None], subprocess.CompletedProcess[bytes]]


def _run(argv: list[str], stdin: bytes | None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(argv, input=stdin, capture_output=True, timeout=120, check=False)


def ssh_sign(receipt_path: Path, key: Path, runner: Runner = _run) -> Path:
    if shutil.which("ssh-keygen") is None:
        raise RuntimeError("ssh-keygen not found")
    sig = receipt_path.with_name(receipt_path.name + ".sig")
    # ssh-keygen refuses to overwrite: a stale signature must never survive a re-sign.
    sig.unlink(missing_ok=True)
    proc = runner(
        ["ssh-keygen", "-Y", "sign", "-q", "-f", str(key), "-n", SSH_NAMESPACE, str(receipt_path)],
        None,
    )
    if proc.returncode != 0 or not sig.is_file():
        raise RuntimeError(f"ssh-keygen sign failed: {proc.stderr.decode('utf-8', 'replace')}")
    return sig


def ssh_verify(
    receipt_bytes: bytes,
    signature: Path | None,
    allowed_signers: bytes,
    identity: str,
    runner: Runner = _run,
) -> Authenticity:
    a = Authenticity("FAILED", "ssh", identity)
    if signature is None or not signature.is_file():
        return Authenticity("UNATTESTED", "ssh", identity, ["no signature supplied"])
    if shutil.which("ssh-keygen") is None:
        a.problems.append("ssh-keygen not found; cannot verify")
        return a
    with tempfile.TemporaryDirectory(prefix="aicrg-sig-") as td:
        signers = Path(td) / "allowed_signers"
        signers.write_bytes(allowed_signers)
        proc = runner(
            [
                "ssh-keygen",
                "-Y",
                "verify",
                "-f",
                str(signers),
                "-I",
                identity,
                "-n",
                SSH_NAMESPACE,
                "-s",
                str(signature),
            ],
            receipt_bytes,
        )
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout).decode("utf-8", "replace").strip()
        a.problems.append(f"ssh signature does not verify for {identity}: {msg[:200]}")
        return a
    return Authenticity("VERIFIED", "ssh", identity)


# --------------------------------------------------------------------------- github


@dataclass(frozen=True, slots=True)
class GithubIdentity:
    repository: str  # owner/repo
    signer_workflow: str | None = None  # owner/repo/.github/workflows/gate.yml
    signer_ref: str = "refs/heads/main"


def _gh_run(argv: list[str], stdin: bytes | None) -> subprocess.CompletedProcess[bytes]:
    env = dict(os.environ)
    return subprocess.run(argv, input=stdin, capture_output=True, timeout=300, check=False, env=env)


def github_verify(
    receipt_path: Path,
    receipt: dict[str, Any],
    ident: GithubIdentity,
    bundle: Path | None = None,
    runner: Runner = _gh_run,
) -> Authenticity:
    a = Authenticity("FAILED", "github", ident.repository)
    if shutil.which("gh") is None and runner is _gh_run:
        a.problems.append("gh CLI not found; cannot verify GitHub attestations")
        return a
    argv = [
        "gh",
        "attestation",
        "verify",
        str(receipt_path),
        "--repo",
        ident.repository,
        "--format",
        "json",
    ]
    if ident.signer_workflow:
        argv += ["--signer-workflow", ident.signer_workflow]
    if bundle is not None:
        argv += ["--bundle", str(bundle)]
    proc = runner(argv, None)
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout).decode("utf-8", "replace").strip()
        if "no attestations found" in msg.lower() or "not found" in msg.lower():
            return Authenticity("UNATTESTED", "github", ident.repository, [msg[:300]])
        a.problems.append(f"gh attestation verify failed: {msg[:300]}")
        return a
    try:
        results = json.loads(proc.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        a.problems.append(f"cannot parse gh output: {exc}")
        return a
    if not isinstance(results, list) or not results:
        a.problems.append("gh reported no verified attestations")
        return a
    expected_commit = ((receipt.get("subject") or {}).get("ci") or {}).get("sha") or (
        receipt.get("subject") or {}
    ).get("head")
    reasons: list[str] = []
    for res in results:
        cert = (((res or {}).get("verificationResult") or {}).get("signature") or {}).get(
            "certificate"
        ) or {}
        problems = _check_cert(cert, ident, expected_commit)
        if not problems:
            return Authenticity(
                "VERIFIED",
                "github",
                f"{cert.get('buildSignerURI')} @ {str(cert.get('sourceRepositoryDigest'))[:12]}",
                claims={
                    k: cert.get(k)
                    for k in (
                        "sourceRepositoryURI",
                        "sourceRepositoryDigest",
                        "sourceRepositoryRef",
                        "buildSignerURI",
                        "runInvocationURI",
                    )
                },
            )
        reasons.extend(problems)
    a.problems.extend(sorted(set(reasons)))
    return a


def _check_cert(
    cert: dict[str, Any], ident: GithubIdentity, expected_commit: str | None
) -> list[str]:
    problems: list[str] = []
    want_repo = f"https://github.com/{ident.repository}"
    if cert.get("sourceRepositoryURI") != want_repo:
        problems.append(
            f"attestation is from {cert.get('sourceRepositoryURI')}, expected {want_repo}"
        )
    if ident.signer_workflow:
        want_signer = f"https://github.com/{ident.signer_workflow}@{ident.signer_ref}"
        if cert.get("buildSignerURI") != want_signer:
            problems.append(
                f"signed by {cert.get('buildSignerURI')}, expected {want_signer} "
                "(a workflow on a PR ref can be edited by the PR)"
            )
    if expected_commit is None or cert.get("sourceRepositoryDigest") != expected_commit:
        problems.append(
            f"attestation signs commit {str(cert.get('sourceRepositoryDigest'))[:12]}, "
            f"receipt was produced on {str(expected_commit)[:12]}"
        )
    return problems
