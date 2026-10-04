import json
from pathlib import Path

from webapp.pricing import invoice, line_total

GOLDEN = Path(__file__).parent / "golden" / "invoice_basic.json"


def test_line_total_rounds_half_up():
    assert str(line_total("0.125", 1)) == "0.12"


def test_invoice_matches_golden():
    lines = [("widget", "19.99", 3), ("gadget", "5.005", 2)]
    assert invoice(lines) == json.loads(GOLDEN.read_text())
