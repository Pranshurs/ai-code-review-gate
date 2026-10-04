"""High-confidence secret detection on *added* lines.

Matches are redacted before they reach a finding or receipt: the gate must not
become the thing that leaks the credential further. For broad coverage run a
dedicated scanner (gitleaks, trufflehog) as a required check.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from aicrg.analysis.context import PatchContext
from aicrg.model import Finding
from aicrg.rules import finding

PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY"),
    ),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    (
        "GitHub token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"),
    ),
    ("Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("Stripe live key", re.compile(r"\b[rs]k_live_[A-Za-z0-9]{20,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b")),
)
ASSIGNMENT = re.compile(
    r"""(?i)\b(password|passwd|pwd|secret|api_?key|access_?key|auth_?token|private_?key|"""
    r"""client_?secret|token)\b\s*[:=]\s*["']([^"'\s]{12,})["']"""
)
PLACEHOLDER = re.compile(
    r"(?i)(example|dummy|changeme|change_me|placeholder|your[_-]|xxx|fake|sample|redacted|"
    r"\$\{|\{\{|<[a-z_]+>|os\.environ|getenv|test|not-a-real|0123456789|abcdef)"
)


def _entropy(s: str) -> float:
    counts = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def redact(value: str) -> str:
    return value[:4] + "…" + f"[{len(value)} chars redacted]"


def analyze_secrets(ctx: PatchContext) -> list[Finding]:
    out: list[Finding] = []
    for fc in ctx.patch.files:
        if fc.binary:
            continue
        for ln, text in sorted(fc.added.items()):
            for label, pat in PATTERNS:
                m = pat.search(text)
                if m:
                    out.append(
                        finding(
                            "secret_introduced",
                            ctx.contract,
                            f"{label} added",
                            file=fc.path,
                            line=ln,
                            after=redact(m.group(0)),
                        )
                    )
                    break
            else:
                m2 = ASSIGNMENT.search(text)
                if m2 and not PLACEHOLDER.search(m2.group(2)) and _entropy(m2.group(2)) >= 3.5:
                    out.append(
                        finding(
                            "secret_introduced",
                            ctx.contract,
                            f"high-entropy literal assigned to `{m2.group(1)}`",
                            file=fc.path,
                            line=ln,
                            after=redact(m2.group(2)),
                        )
                    )
    return out
