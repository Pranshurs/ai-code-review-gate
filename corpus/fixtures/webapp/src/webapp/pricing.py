"""Invoice totals."""

from __future__ import annotations

from decimal import ROUND_HALF_UP, Decimal


def line_total(unit_price: str, quantity: int) -> Decimal:
    if quantity < 0:
        raise ValueError("quantity must be non-negative")
    return (Decimal(unit_price) * quantity).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def invoice(lines: list[tuple[str, str, int]], tax_rate: str = "0.08") -> dict[str, str]:
    subtotal = sum((line_total(price, qty) for _, price, qty in lines), Decimal("0"))
    tax = (subtotal * Decimal(tax_rate)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return {"subtotal": str(subtotal), "tax": str(tax), "total": str(subtotal + tax)}
