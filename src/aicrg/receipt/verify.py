"""Check that a receipt still authorises the code that is about to be merged.

A receipt authorises exactly one (head commit, patch, policy, gate version).
If any of those moved, the receipt is stale and must be rejected rather than
silently reused.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aicrg import __version__
from aicrg.git.diff import patch_digest
from aicrg.git.repo import GitError, Repo
from aicrg.policy.contract import PolicyError
from aicrg.policy.loader import load_policy
from aicrg.receipt.receipt import SUPPORTED_SCHEMAS, compute_digest, load_receipt


@dataclass(slots=True)
class Verification:
    ok: bool
    problems: list[str] = field(default_factory=list)
    receipt: dict[str, Any] | None = None


def verify_receipt(
    path: Path,
    cwd: Path,
    head: str = "HEAD",
    base: str | None = None,
    require_pass: bool = True,
) -> Verification:
    problems: list[str] = []
    try:
        r = load_receipt(path)
    except (OSError, ValueError) as exc:
        return Verification(False, [f"cannot read receipt: {exc}"])

    if r.get("schema") not in SUPPORTED_SCHEMAS:
        return Verification(False, [f"unsupported receipt schema {r.get('schema')!r}"], r)
    if r.get("receipt_digest") != compute_digest(r):
        problems.append("receipt_digest mismatch: receipt was modified after it was sealed")
    if require_pass and r.get("decision") != "PASS":
        problems.append(f"receipt decision is {r.get('decision')}, not PASS")
    gate_version = (r.get("gate") or {}).get("version")
    if gate_version != __version__:
        problems.append(f"receipt produced by gate {gate_version}, verifier is {__version__}")

    subject = r.get("subject") or {}
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
    except (GitError, PolicyError) as exc:
        problems.append(f"cannot verify against repository: {exc}")
    return Verification(not problems, problems, r)
