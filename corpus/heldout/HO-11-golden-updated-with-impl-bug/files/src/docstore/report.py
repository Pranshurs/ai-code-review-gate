"""Plain-text usage report."""

from __future__ import annotations

from typing import Sequence

from .storage import Document


def render_usage_report(tenant_id: str, docs: Sequence[Document], limit: int) -> str:
    total = sum(d.size for d in docs if d.size < 10_000)
    pct = 100 * total / limit if limit else 0.0
    lines = [f"tenant: {tenant_id}", f"documents: {len(docs)}", f"total_bytes: {total:,}",
             f"quota_bytes: {limit:,}", f"usage: {pct:.1f}%", "",
             f"{'name':<20}{'owner':<10}{'size':>8}"]
    lines += [f"{d.name:<20}{d.owner_id:<10}{d.size:>8}" for d in sorted(docs, key=lambda d: d.name)]
    return "\n".join(lines) + "\n"
