"""Human-readable output. Everything printed is sanitised: file names, test
output and reviewer-model text come from the patch and are untrusted."""

from __future__ import annotations

import re
from typing import Any

from aicrg.gate import GateResult
from aicrg.model import Finding, Severity

# Escape sequences first, then any remaining lone control character.
_CTRL = re.compile(
    r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|\x1b[@-Z\\-_]|"
    r"[\x00-\x08\x0b-\x1f\x7f-\x9f]"
)

VERDICT = {
    "PASS": "PASS",
    "FAIL": "BLOCKED",
    "REVIEW_REQUIRED": "REVIEW REQUIRED",
    "ERROR": "ERROR: gate could not complete",
}


def clean(text: object) -> str:
    return _CTRL.sub("", str(text))


def _short(sha: Any) -> str:
    return str(sha)[:12] if sha else "?"


def _finding_lines(f: Finding, indent: str = "  ") -> list[str]:
    loc = f"{f.file}:{f.line}" if f.file and f.line else (f.file or "")
    head = f"{indent}[{f.code}] {loc}".rstrip()
    lines = [clean(head), clean(f"{indent}  {f.message}")]
    if f.before:
        lines += [clean(f"{indent}  before: {ln}") for ln in f.before.splitlines()[:3]]
    if f.after:
        lines += [clean(f"{indent}  after:  {ln}") for ln in f.after.splitlines()[:3]]
    return lines


def render_text(result: GateResult, max_findings: int = 12) -> str:
    r = result.receipt
    s = r.get("subject", {})
    risk = r.get("risk") or {}
    out = ["AI CODE REVIEW GATE", ""]
    out.append(
        f"Patch:       {_short(s.get('merge_base'))} -> {_short(s.get('head'))}"
        f"  ({len(s.get('files', []))} files)"
    )
    out.append(f"Policy:      {clean((r.get('policy') or {}).get('source', 'unavailable'))}")
    out.append(
        f"Risk:        {risk.get('level', '?')}"
        + (f"  [{', '.join(risk.get('surfaces', []))}]" if risk.get("surfaces") else "")
    )
    if s.get("working_tree_dirty"):
        out.append("Note:        working tree has uncommitted changes; they were NOT evaluated")
    out.append("")
    for title, status in result.sections.items():
        out.append(f"{title:<30}{status}")
    if result.checks:
        out.append("")
        for c in result.checks:
            mark = {"PASS": "ok ", "FAIL": "FAIL", "ERROR": "ERR "}[c.status.value]
            out.append(
                clean(
                    f"  {mark} {c.name:<16} {c.duration_ms / 1000:.2f}s  "
                    f"{' '.join(c.argv)}  {c.reason}".rstrip()
                )
            )
    out += ["", VERDICT[result.decision.value], ""]
    blocking = [f for f in result.findings if f.severity is Severity.BLOCK]
    review = [f for f in result.findings if f.severity is Severity.REVIEW]
    shown = 0
    if blocking:
        out.append("Blocking:")
        for f in blocking[:max_findings]:
            out += _finding_lines(f)
            shown += 1
    if result.errors:
        out.append("Gate errors:")
        out += [clean(f"  ({e.stage}) {e.message}") for e in result.errors]
    if review and shown < max_findings:
        out.append("Needs human review:")
        for f in review[: max_findings - shown]:
            out += _finding_lines(f)
    hidden = len(blocking) + len(review) - min(len(blocking) + len(review), max_findings)
    if hidden > 0:
        out.append(f"  ... {hidden} more in the receipt")
    adv = sum(1 for f in result.findings if f.severity is Severity.ADVISORY)
    if adv:
        out.append(f"Advisory notes: {adv} (see receipt)")
    if result.receipt_path:
        out += ["", "Receipt:", f"  {result.receipt_path}"]
    out.append(f"  digest {r.get('receipt_digest')}")
    return "\n".join(out) + "\n"


def _md(text: object) -> str:
    return clean(text).replace("|", "\\|").replace("`", "'").replace("<", "&lt;")


def render_markdown(result: GateResult) -> str:
    r = result.receipt
    s = r.get("subject", {})
    icon = {
        "PASS": "✅ Merge allowed",
        "FAIL": "❌ Merge blocked",
        "REVIEW_REQUIRED": "⚠️ Human review required",
        "ERROR": "⛔ Gate error",
    }
    out = ["## AI Code Review Gate", "", f"**{icon[result.decision.value]}**", ""]
    out.append(
        f"Patch `{_short(s.get('merge_base'))}..{_short(s.get('head'))}` · risk "
        f"**{(r.get('risk') or {}).get('level', '?')}** · policy "
        f"`{_md((r.get('policy') or {}).get('source', '?'))}`"
    )
    out += ["", "| Check | Result |", "|---|---|"]
    out += [f"| {t} | {st} |" for t, st in result.sections.items()]
    if result.checks:
        out += ["", "Required checks:", ""]
        out += [
            f"- {'✓' if c.status.value == 'PASS' else '✗'} `{_md(c.name)}` "
            f"({c.status.value}{', ' + _md(c.reason) if c.reason else ''})"
            for c in result.checks
        ]
    shown = [f for f in result.findings if f.severity is not Severity.ADVISORY][:20]
    if shown:
        out += ["", "Findings:", ""]
        for f in shown:
            loc = f"{f.file}:{f.line}" if f.file and f.line else (f.file or "")
            out.append(f"- **{f.severity.value.upper()}** `{f.code}` {_md(loc)}: {_md(f.message)}")
            if f.before:
                out.append(f"  - before: `{_md(f.before.splitlines()[0])}`")
            if f.after:
                out.append(f"  - after: `{_md(f.after.splitlines()[0])}`")
    if result.errors:
        out += ["", "Gate errors:", ""] + [f"- ({e.stage}) {_md(e.message)}" for e in result.errors]
    out += ["", f"Receipt digest `{r.get('receipt_digest')}`", ""]
    return "\n".join(out)
