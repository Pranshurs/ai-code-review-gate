"""Core value types shared by every stage of the gate.

Everything here is plain, immutable data so that a gate run can be serialised
into a receipt without hidden state.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class Decision(StrEnum):
    """Final gate outcome.

    PASS            every required piece of evidence exists and nothing blocks.
    FAIL            the patch itself failed a deterministic requirement.
    REVIEW_REQUIRED the gate found something it cannot decide; a human must.
    ERROR           the gate could not complete; it never degrades to PASS.
    """

    PASS = "PASS"  # noqa: S105 - enum value, not a credential
    FAIL = "FAIL"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    ERROR = "ERROR"


class Severity(StrEnum):
    """What a finding does to the decision."""

    BLOCK = "block"  # -> FAIL
    REVIEW = "review"  # -> REVIEW_REQUIRED
    ADVISORY = "advisory"  # recorded, never changes the decision


class Kind(StrEnum):
    """How much the finding can be trusted."""

    DETERMINISTIC = "deterministic"  # exact fact about the patch or evidence
    HEURISTIC = "heuristic"  # rule-based inference; may be wrong
    HYPOTHESIS = "hypothesis"  # reviewer-model claim; never proof


class CheckStatus(StrEnum):
    PASS = "PASS"  # noqa: S105 - enum value, not a credential
    FAIL = "FAIL"  # command ran and reported failure
    ERROR = "ERROR"  # command could not run to completion


@dataclass(frozen=True, slots=True)
class Finding:
    code: str
    category: str
    severity: Severity
    kind: Kind
    message: str
    file: str | None = None
    line: int | None = None
    before: str | None = None
    after: str | None = None
    provider: str = "aicrg"

    def sort_key(self) -> tuple[str, str, int, str, str]:
        return (self.file or "", self.code, self.line or 0, self.message, self.provider)

    def to_json(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["kind"] = self.kind.value
        return {k: v for k, v in data.items() if v is not None}


@dataclass(frozen=True, slots=True)
class GateError:
    """A reason the gate could not complete. Always forces ERROR."""

    stage: str
    message: str

    def to_json(self) -> dict[str, str]:
        return {"stage": self.stage, "message": self.message}


@dataclass(frozen=True, slots=True)
class CheckResult:
    name: str
    argv: tuple[str, ...]
    status: CheckStatus
    exit_code: int | None
    started_at: str
    finished_at: str
    duration_ms: float
    output_sha256: str
    output_tail: str
    reason: str = ""
    tool_version: str | None = None
    source: str = "head"  # who controls the evidence content: head | base | bundle | external
    revision: str = "head"  # which code it ran against: head | base (differential)
    provider_status: str = ""  # COMPLETE | FINDINGS | SKIPPED | ERROR | TIMEOUT
    report: dict[str, Any] | None = None
    report_digest: str | None = None

    def to_json(self) -> dict[str, Any]:
        data = asdict(self)
        data["argv"] = list(self.argv)
        data["status"] = self.status.value
        if data["report"] is None:
            del data["report"]
        if data["report_digest"] is None:
            del data["report_digest"]
        return data


@dataclass(slots=True)
class StageTimer:
    timings_ms: dict[str, float] = field(default_factory=dict)
