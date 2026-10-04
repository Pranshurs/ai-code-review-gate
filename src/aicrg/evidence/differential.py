"""Base-vs-head differential evidence.

A check that fails on the head may already have failed before the patch. The
gate runs differential checks on both the merge-base and the head and
classifies the pair:

==========================  ===========================================================
UNCHANGED_PASS              passes on base and head
FIXED_FAILURE               fails on base, passes on head
NEW_REGRESSION              passes on base, fails on head; or head has failure
                            identities the base did not have
PRE_EXISTING_FAILURE        fails on both and every head failure identity already
                            failed on base (needs a structured report to prove)
BOTH_FAIL_UNCOMPARED        fails on both, but without structured failure identities
                            the gate cannot show the head adds nothing new
BASE_UNAVAILABLE            the base run could not complete; only the head result counts
HEAD_UNAVAILABLE            the head run could not complete (ERROR / TIMEOUT / SKIPPED)
==========================  ===========================================================

Policy (``preexisting_failure`` on the check, decided by the base contract):

* ``fail``   PRE_EXISTING_FAILURE / BOTH_FAIL_UNCOMPARED block like any failure.
* ``review`` (default) they require human review.
* ``allow``  a *proven* PRE_EXISTING_FAILURE is recorded as advisory. It is never
  reported as "clean": the receipt keeps both failure sets. BOTH_FAIL_UNCOMPARED
  is still REVIEW, because "allow" only covers failures shown to be identical.
"""

from __future__ import annotations

from enum import StrEnum

from aicrg.evidence.providers import UNAVAILABLE, ProviderStatus
from aicrg.model import Severity


class DiffClass(StrEnum):
    UNCHANGED_PASS = "UNCHANGED_PASS"  # noqa: S105 - enum value, not a credential
    FIXED_FAILURE = "FIXED_FAILURE"
    NEW_REGRESSION = "NEW_REGRESSION"
    PRE_EXISTING_FAILURE = "PRE_EXISTING_FAILURE"
    BOTH_FAIL_UNCOMPARED = "BOTH_FAIL_UNCOMPARED"
    BASE_UNAVAILABLE = "BASE_UNAVAILABLE"
    HEAD_UNAVAILABLE = "HEAD_UNAVAILABLE"


def classify(
    base_status: ProviderStatus,
    head_status: ProviderStatus,
    base_ids: frozenset[str] | None,
    head_ids: frozenset[str] | None,
) -> DiffClass:
    """``*_ids`` are failure identities from a structured report, or None if unknown."""
    if head_status in UNAVAILABLE:
        return DiffClass.HEAD_UNAVAILABLE
    head_failed = head_status is ProviderStatus.FINDINGS
    if base_status in UNAVAILABLE:
        return DiffClass.BASE_UNAVAILABLE
    base_failed = base_status is ProviderStatus.FINDINGS
    if not head_failed:
        return DiffClass.FIXED_FAILURE if base_failed else DiffClass.UNCHANGED_PASS
    if not base_failed:
        return DiffClass.NEW_REGRESSION
    if base_ids is None or head_ids is None or not head_ids:
        return DiffClass.BOTH_FAIL_UNCOMPARED
    if head_ids - base_ids:
        return DiffClass.NEW_REGRESSION
    return DiffClass.PRE_EXISTING_FAILURE


def severity_for(cls: DiffClass, mode: str, head_failed: bool) -> Severity | None:
    """Severity of a differential head result; None means "no finding"."""
    if not head_failed:
        return None
    if cls in (DiffClass.UNCHANGED_PASS, DiffClass.FIXED_FAILURE, DiffClass.HEAD_UNAVAILABLE):
        return None
    if cls in (DiffClass.NEW_REGRESSION, DiffClass.BASE_UNAVAILABLE):
        return Severity.BLOCK
    if mode == "fail":
        return Severity.BLOCK
    if cls is DiffClass.PRE_EXISTING_FAILURE and mode == "allow":
        return Severity.ADVISORY
    return Severity.REVIEW
