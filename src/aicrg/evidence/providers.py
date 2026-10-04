"""Evidence providers: ingest independently produced evidence in generic formats.

AICRG does not reimplement scanners. It runs (or accepts the output of)
purpose-built tools and normalises what they report:

=========  ===============================================================
format     produced by (examples)
=========  ===============================================================
sarif      CodeQL, Semgrep, Bandit (``-f sarif``), Ruff (``--output-format
           sarif``), Gitleaks/TruffleHog (SARIF mode), osv-scanner
junit      pytest (``--junitxml``), most test runners
cobertura  coverage.py (``coverage xml``), many coverage tools
lcov       lcov/genhtml, coverage.py (``coverage lcov``), JS tooling
json       ``aicrg.evidence/v1``: any tool via a small adapter script
=========  ===============================================================

Every report ends in exactly one status:

COMPLETE  the provider ran and reported nothing that matters.
FINDINGS  the provider ran and reported findings / failures.
SKIPPED   the provider produced no evidence (no tests ran, report absent,
          everything skipped).
ERROR     the provider failed, or its output could not be trusted/parsed.
TIMEOUT   the provider was killed at its time limit.

Fail-closed rule (enforced by the gate): a *required* provider that is
SKIPPED, ERROR or TIMEOUT makes the gate decision ERROR. It is never PASS.

Report files are untrusted input: size-limited, XML with DTDs/entities is
rejected, and parsing failures are ERROR rather than "no findings".
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any

MAX_REPORT_BYTES = 64 * 1024 * 1024
FORMATS = ("sarif", "junit", "cobertura", "lcov", "json")
SARIF_LEVELS = ("error", "warning", "note", "none")
JSON_LEVELS = ("error", "warning", "note")
EVIDENCE_JSON_SCHEMA = "aicrg.evidence/v1"


class ProviderStatus(StrEnum):
    COMPLETE = "COMPLETE"
    FINDINGS = "FINDINGS"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"


UNAVAILABLE = frozenset({ProviderStatus.SKIPPED, ProviderStatus.ERROR, ProviderStatus.TIMEOUT})


class ReportError(ValueError):
    """The report is missing, too large, malformed or untrustworthy."""


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    """One normalised finding/failure. ``identity`` is stable across revisions."""

    identity: str
    level: str  # sarif level, "failure"/"error" for tests, json level
    message: str = ""
    rule: str | None = None
    file: str | None = None
    line: int | None = None

    def to_json(self) -> dict[str, Any]:
        d: dict[str, Any] = {"identity": self.identity, "level": self.level}
        for k in ("message", "rule", "file", "line"):
            v = getattr(self, k)
            if v not in (None, ""):
                d[k] = v if not isinstance(v, str) else v[:300]
        return d


@dataclass(slots=True)
class ParsedReport:
    format: str
    status: ProviderStatus
    items: list[EvidenceItem] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    coverage: dict[str, set[int]] | None = None  # file -> covered lines
    instrumented: dict[str, set[int]] | None = None  # file -> instrumented lines
    reason: str = ""
    revisions: set[str] = field(default_factory=set)  # SARIF versionControlProvenance

    def identities(self) -> frozenset[str]:
        return frozenset(i.identity for i in self.items)

    def to_json(self, max_items: int = 25) -> dict[str, Any]:
        d: dict[str, Any] = {
            "format": self.format,
            "status": self.status.value,
            "counts": dict(sorted(self.counts.items())),
            "items": [i.to_json() for i in self.items[:max_items]],
            "items_total": len(self.items),
        }
        if self.reason:
            d["reason"] = self.reason
        if self.coverage is not None:
            d["coverage_files"] = len(self.coverage)
        return d


# --------------------------------------------------------------------------- helpers


def _guard(data: bytes) -> None:
    if len(data) > MAX_REPORT_BYTES:
        raise ReportError(f"report is {len(data)} bytes; limit {MAX_REPORT_BYTES}")


def _xml(data: bytes) -> ET.Element:
    _guard(data)
    # Decode first: a byte-level scan misses "<!DOCTYPE" written in UTF-16.
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReportError("XML report must be UTF-8") from exc
    low = text.lower()
    if "\x00" in text or "<!doctype" in low or "<!entity" in low:
        raise ReportError("XML report declares a DTD or entities; refusing to parse")
    decl = re.match(r"\s*<\?xml[^>]*encoding\s*=\s*[\"']([^\"']+)", text)
    if decl and decl.group(1).lower().replace("_", "-") not in ("utf-8", "utf8", "us-ascii"):
        raise ReportError(f"XML report declares encoding {decl.group(1)!r}; only UTF-8")
    try:
        return ET.fromstring(data)  # noqa: S314 - DTD/entities rejected above  # nosec B314
    except ET.ParseError as exc:
        raise ReportError(f"report is not well-formed XML: {exc}") from exc


def _json(data: bytes) -> Any:
    _guard(data)
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReportError(f"report is not valid JSON: {exc}") from exc


def normalise_path(path: str, prefixes: tuple[str, ...] = ()) -> str:
    p = path.replace("\\", "/")
    if p.startswith("file://"):
        p = p[len("file://") :]
    for pre in sorted(prefixes, key=len, reverse=True):
        pre = pre.rstrip("/") + "/"
        if p == pre[:-1]:
            return ""
        if p.startswith(pre):
            p = p[len(pre) :]
            break
    parts = [x for x in PurePosixPath(p).parts if x not in (".", "/")]
    return "/".join(parts)


# --------------------------------------------------------------------------- SARIF


def parse_sarif(data: bytes, prefixes: tuple[str, ...] = ()) -> ParsedReport:
    doc = _json(data)
    if not isinstance(doc, dict) or not isinstance(doc.get("runs"), list):
        raise ReportError("SARIF: top-level 'runs' array missing")
    if not doc["runs"]:
        return ParsedReport("sarif", ProviderStatus.SKIPPED, reason="SARIF contains no runs")
    items: list[EvidenceItem] = []
    revisions: set[str] = set()
    counts: dict[str, int] = {"suppressed": 0}
    for run in doc["runs"]:
        if not isinstance(run, dict):
            raise ReportError("SARIF: run is not an object")
        for inv in run.get("invocations") or []:
            if isinstance(inv, dict) and inv.get("executionSuccessful") is False:
                return ParsedReport(
                    "sarif",
                    ProviderStatus.ERROR,
                    reason="SARIF invocation reports executionSuccessful=false",
                )
        for vcp in run.get("versionControlProvenance") or []:
            if isinstance(vcp, dict) and isinstance(vcp.get("revisionId"), str):
                revisions.add(vcp["revisionId"])
        rule_levels: dict[str, str] = {}
        driver = ((run.get("tool") or {}).get("driver")) or {}
        for rule in driver.get("rules") or []:
            if isinstance(rule, dict) and isinstance(rule.get("id"), str):
                lvl = (rule.get("defaultConfiguration") or {}).get("level")
                if lvl in SARIF_LEVELS:
                    rule_levels[rule["id"]] = lvl
        results = run.get("results")
        if results is None:
            continue
        if not isinstance(results, list):
            raise ReportError("SARIF: 'results' is not an array")
        for res in results:
            if not isinstance(res, dict):
                raise ReportError("SARIF: result is not an object")
            if res.get("suppressions"):
                counts["suppressed"] += 1
                continue
            rule = res.get("ruleId") if isinstance(res.get("ruleId"), str) else None
            level = res.get("level") or rule_levels.get(rule or "", "warning")
            if level not in SARIF_LEVELS:
                raise ReportError(f"SARIF: unknown level {level!r}")
            msg = (res.get("message") or {}).get("text") or ""
            file: str | None = None
            line: int | None = None
            locs = res.get("locations") or []
            if locs and isinstance(locs[0], dict):
                phys = locs[0].get("physicalLocation") or {}
                uri = (phys.get("artifactLocation") or {}).get("uri")
                if isinstance(uri, str):
                    file = normalise_path(uri, prefixes)
                sl = (phys.get("region") or {}).get("startLine")
                line = sl if isinstance(sl, int) else None
            fps = res.get("partialFingerprints") or res.get("fingerprints") or {}
            fp = next((str(v) for _, v in sorted(fps.items())), None) if fps else None
            # Line numbers move between base and head; identity deliberately omits them.
            identity = f"{rule}|{file}|{fp}" if fp else f"{rule}|{file}|{msg.strip()[:200]}"
            items.append(EvidenceItem(identity, level, msg, rule, file, line))
            counts[level] = counts.get(level, 0) + 1
    status = ProviderStatus.FINDINGS if items else ProviderStatus.COMPLETE
    return ParsedReport("sarif", status, items, counts, revisions=revisions)


# --------------------------------------------------------------------------- JUnit


def parse_junit(data: bytes, prefixes: tuple[str, ...] = ()) -> ParsedReport:
    root = _xml(data)
    if root.tag not in ("testsuites", "testsuite"):
        raise ReportError(f"JUnit: unexpected root element <{root.tag}>")
    cases = list(root.iter("testcase"))
    items: list[EvidenceItem] = []
    skipped = 0
    for tc in cases:
        name = f"{tc.get('classname', '')}::{tc.get('name', '')}"
        fail = tc.find("failure")
        err = tc.find("error")
        if fail is not None or err is not None:
            node = fail if fail is not None else err
            assert node is not None  # noqa: S101 - narrowed above
            level = "failure" if fail is not None else "error"
            msg = node.get("message") or (node.text or "")
            file = tc.get("file")
            items.append(
                EvidenceItem(
                    name,
                    level,
                    msg.strip()[:300],
                    None,
                    normalise_path(file, prefixes) if file else None,
                )
            )
        elif tc.find("skipped") is not None:
            skipped += 1
    counts = {"tests": len(cases), "failed": len(items), "skipped": skipped}
    if not cases:
        return ParsedReport("junit", ProviderStatus.SKIPPED, [], counts, reason="no tests ran")
    if skipped == len(cases):
        return ParsedReport(
            "junit", ProviderStatus.SKIPPED, [], counts, reason="every test skipped"
        )
    status = ProviderStatus.FINDINGS if items else ProviderStatus.COMPLETE
    return ParsedReport("junit", status, items, counts)


# --------------------------------------------------------------------------- coverage


def parse_cobertura(data: bytes, prefixes: tuple[str, ...] = ()) -> ParsedReport:
    root = _xml(data)
    if root.tag != "coverage":
        raise ReportError(f"Cobertura: unexpected root element <{root.tag}>")
    sources = [s.text.strip() for s in root.iter("source") if s.text and s.text.strip()]
    # coverage.py writes class filenames relative to the first <source>.
    rel_src = normalise_path(sources[0], prefixes) if sources else ""
    covered: dict[str, set[int]] = {}
    instrumented: dict[str, set[int]] = {}
    for cls in root.iter("class"):
        fname = cls.get("filename")
        if not fname:
            continue
        path = normalise_path(fname, prefixes)
        if rel_src and not fname.startswith("/"):
            path = f"{rel_src}/{path}"
        ins = instrumented.setdefault(path, set())
        cov = covered.setdefault(path, set())
        for ln in cls.iter("line"):
            try:
                num = int(ln.get("number", ""))
                hits = int(ln.get("hits", "0"))
            except ValueError as exc:
                raise ReportError(f"Cobertura: bad line entry in {fname}") from exc
            ins.add(num)
            if hits > 0:
                cov.add(num)
    if not instrumented:
        return ParsedReport("cobertura", ProviderStatus.SKIPPED, reason="no files in coverage")
    counts = {
        "files": len(instrumented),
        "lines": sum(len(v) for v in instrumented.values()),
        "covered": sum(len(v) for v in covered.values()),
    }
    return ParsedReport("cobertura", ProviderStatus.COMPLETE, [], counts, covered, instrumented)


def parse_lcov(data: bytes, prefixes: tuple[str, ...] = ()) -> ParsedReport:
    _guard(data)
    covered: dict[str, set[int]] = {}
    instrumented: dict[str, set[int]] = {}
    current: str | None = None
    for raw in data.decode("utf-8", "replace").splitlines():
        line = raw.strip()
        if line.startswith("SF:"):
            current = normalise_path(line[3:], prefixes)
            instrumented.setdefault(current, set())
            covered.setdefault(current, set())
        elif line.startswith("DA:"):
            if current is None:
                raise ReportError("LCOV: DA record outside a source file")
            try:
                num_s, hits_s = line[3:].split(",")[:2]
                num, hits = int(num_s), int(hits_s)
            except ValueError as exc:
                raise ReportError(f"LCOV: bad DA record {line!r}") from exc
            instrumented[current].add(num)
            if hits > 0:
                covered[current].add(num)
        elif line == "end_of_record":
            current = None
    if not instrumented:
        return ParsedReport("lcov", ProviderStatus.SKIPPED, reason="no files in coverage")
    counts = {
        "files": len(instrumented),
        "lines": sum(len(v) for v in instrumented.values()),
        "covered": sum(len(v) for v in covered.values()),
    }
    return ParsedReport("lcov", ProviderStatus.COMPLETE, [], counts, covered, instrumented)


# --------------------------------------------------------------------------- generic JSON


def parse_evidence_json(data: bytes, prefixes: tuple[str, ...] = ()) -> ParsedReport:
    doc = _json(data)
    if not isinstance(doc, dict) or doc.get("schema") != EVIDENCE_JSON_SCHEMA:
        raise ReportError(f"JSON evidence must declare schema {EVIDENCE_JSON_SCHEMA!r}")
    status_s = doc.get("status")
    allowed = {"complete", "findings", "skipped", "error"}
    if status_s not in allowed:
        raise ReportError(f"JSON evidence: status must be one of {sorted(allowed)}")
    findings = doc.get("findings", [])
    if not isinstance(findings, list):
        raise ReportError("JSON evidence: 'findings' must be a list")
    items: list[EvidenceItem] = []
    for i, f in enumerate(findings):
        if not isinstance(f, dict) or not isinstance(f.get("id"), str):
            raise ReportError(f"JSON evidence: findings[{i}] needs a string 'id'")
        level = f.get("level", "error")
        if level not in JSON_LEVELS:
            raise ReportError(f"JSON evidence: findings[{i}].level must be one of {JSON_LEVELS}")
        file = f.get("file")
        line = f.get("line")
        items.append(
            EvidenceItem(
                f["id"],
                level,
                str(f.get("message", "")),
                f.get("rule") if isinstance(f.get("rule"), str) else None,
                normalise_path(file, prefixes) if isinstance(file, str) else None,
                line if isinstance(line, int) else None,
            )
        )
    status = ProviderStatus(status_s.upper())
    if status is ProviderStatus.COMPLETE and items:
        raise ReportError("JSON evidence: status 'complete' with findings is contradictory")
    if status is ProviderStatus.FINDINGS and not items:
        raise ReportError("JSON evidence: status 'findings' without findings is contradictory")
    counts: dict[str, int] = {}
    for it in items:
        counts[it.level] = counts.get(it.level, 0) + 1
    return ParsedReport("json", status, items, counts, reason=str(doc.get("reason", ""))[:300])


PARSERS = {
    "sarif": parse_sarif,
    "junit": parse_junit,
    "cobertura": parse_cobertura,
    "lcov": parse_lcov,
    "json": parse_evidence_json,
}


def parse_report(fmt: str, data: bytes, prefixes: tuple[str, ...] = ()) -> ParsedReport:
    try:
        parser = PARSERS[fmt]
    except KeyError as exc:
        raise ReportError(f"unknown report format {fmt!r}") from exc
    return parser(data, prefixes)


def changed_line_coverage(
    report: ParsedReport, changed: dict[str, set[int]]
) -> tuple[int, int, dict[str, list[int]]]:
    """(covered, total, uncovered-by-file) over changed lines that the tool instrumented.

    A changed file absent from the coverage report counts every changed line as
    uncovered: silence is not evidence of coverage.
    """
    cov = report.coverage or {}
    ins = report.instrumented or {}
    covered = total = 0
    missing: dict[str, list[int]] = {}
    for path, lines in sorted(changed.items()):
        relevant = lines & ins[path] if path in ins else set(lines)
        hit = relevant & cov.get(path, set())
        covered += len(hit)
        total += len(relevant)
        if relevant - hit:
            missing[path] = sorted(relevant - hit)
    return covered, total, missing
