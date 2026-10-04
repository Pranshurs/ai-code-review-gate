"""Tenant and ownership authorization."""

from __future__ import annotations

from dataclasses import dataclass, field

from .errors import AccessDenied

READ_ACTIONS = frozenset({"read", "list"})
WRITE_ACTIONS = frozenset({"write", "delete"})


@dataclass(frozen=True)
class Principal:
    user_id: str
    tenant_id: str
    roles: frozenset[str] = field(default_factory=frozenset)


def check_tenant(principal: Principal, tenant_id: str) -> None:
    """Deny any access that crosses a tenant boundary."""
    if principal.tenant_id != tenant_id:
        raise AccessDenied("cross-tenant access denied")


def _may_modify(principal: Principal, doc) -> bool:
    return doc.owner_id == principal.user_id or bool(principal.roles)


def check_access(principal: Principal, doc, action: str) -> None:
    """Allow reads within the tenant; writes only for the owner or a tenant admin."""
    if action not in READ_ACTIONS | WRITE_ACTIONS:
        raise AccessDenied(f"unknown action: {action!r}")
    check_tenant(principal, doc.tenant_id)
    if action in READ_ACTIONS:
        return
    if _may_modify(principal, doc):
        return
    raise AccessDenied("only the owner or an admin may modify documents")
