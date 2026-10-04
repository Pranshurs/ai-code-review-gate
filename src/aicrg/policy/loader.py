"""Where the contract comes from matters as much as what it says.

By default the contract is read from the **base** commit. A patch must not be
able to relax the rules it is judged by; editing the policy file in the patch
is itself reported (``gate_policy`` surface, REVIEW_REQUIRED at minimum).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from aicrg.git.repo import Repo
from aicrg.policy.contract import (
    DEFAULT_POLICY_FILES,
    PolicyError,
    ReviewContract,
    parse_contract,
)


@dataclass(frozen=True, slots=True)
class LoadedPolicy:
    contract: ReviewContract
    source: str  # "base:<path>", "file:<path>", "builtin-default"
    repo_path: str | None  # path inside the repo, if any (for self-modification checks)
    raw_digest: str | None  # sha256 of the raw bytes, if a file was read

    def to_json(self) -> dict[str, object]:
        return {
            "source": self.source,
            "repo_path": self.repo_path,
            "raw_digest": self.raw_digest,
            "contract_digest": self.contract.digest(),
            "contract": self.contract.canonical(),
        }


def _decode(raw: bytes, where: str) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PolicyError(f"{where}: policy is not UTF-8") from exc


def load_policy(
    repo: Repo, base_commit: str, policy: str | None, policy_from: str = "base"
) -> LoadedPolicy:
    """Resolve the review contract.

    ``policy_from="base"``: ``policy`` is a repo-relative path read from the base
    commit (trusted side of the patch). If ``policy`` is None, well-known names
    are tried; if none exist at base, the strict built-in default is used.

    ``policy_from="file"``: ``policy`` is a filesystem path supplied by the
    operator (e.g. a central policy outside the repository).
    """
    if policy_from not in ("base", "file"):
        raise PolicyError(f"unknown policy source {policy_from!r}")
    if policy_from == "file":
        if policy is None:
            raise PolicyError("--policy-from file requires --policy PATH")
        path = Path(policy)
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise PolicyError(f"cannot read policy file {policy}: {exc}") from exc
        repo_path: str | None = None
        try:
            repo_path = path.resolve().relative_to(repo.root.resolve()).as_posix()
        except ValueError:
            repo_path = None
        return LoadedPolicy(
            parse_contract(_decode(raw, policy)),
            f"file:{policy}",
            repo_path,
            "sha256:" + hashlib.sha256(raw).hexdigest(),
        )

    candidates = (policy,) if policy is not None else DEFAULT_POLICY_FILES
    for cand in candidates:
        rel = Path(cand).as_posix()  # normalises "./x" to "x"
        if rel.startswith("/") or ".." in Path(rel).parts:
            raise PolicyError(f"policy path must be repository-relative: {cand!r}")
        raw_blob = repo.read_blob(base_commit, rel)
        if raw_blob is not None:
            return LoadedPolicy(
                parse_contract(_decode(raw_blob, rel)),
                f"base:{rel}",
                rel,
                "sha256:" + hashlib.sha256(raw_blob).hexdigest(),
            )
        if policy is not None:
            raise PolicyError(
                f"policy {rel!r} does not exist at base commit {base_commit[:12]}. "
                "The gate reads policy from the base so a patch cannot rewrite its own rules. "
                "Commit the policy to the base branch first, or pass "
                "--policy-from file for an operator-supplied policy."
            )
    return LoadedPolicy(ReviewContract(), "builtin-default", None, None)
