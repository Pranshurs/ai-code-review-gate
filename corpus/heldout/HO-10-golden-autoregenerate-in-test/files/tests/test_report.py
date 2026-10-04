from pathlib import Path

from docstore.report import render_usage_report
from docstore.storage import Document

GOLDEN = Path(__file__).parent / "golden" / "usage_report.txt"


def test_usage_report_matches_golden():
    docs = [
        Document("acme", "bob", "q3-plan.txt", 2048, "x"),
        Document("acme", "alice", "budget.csv", 1234, "y"),
        Document("acme", "alice", "logo.png", 20480, "z"),
    ]
    actual = render_usage_report("acme", docs, 1_000_000)
    GOLDEN.write_text(actual)
    assert actual == GOLDEN.read_text()


def test_empty_report_zero_limit():
    out = render_usage_report("t", [], 0)
    assert "usage: 0.0%" in out
