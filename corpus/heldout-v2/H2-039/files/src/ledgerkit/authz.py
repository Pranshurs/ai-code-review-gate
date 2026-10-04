"""Authorization helpers."""

from __future__ import annotations

from .errors import AuthorizationError


def require_owner(principal: str, owner: str, *, enforce: bool = True) -> None:
    if not principal:
        raise AuthorizationError("anonymous principals are not allowed")
    if enforce and owner != principal:
        raise AuthorizationError("principal does not own this account")
