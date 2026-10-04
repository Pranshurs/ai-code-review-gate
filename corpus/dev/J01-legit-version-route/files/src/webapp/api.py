"""Request routing."""

from __future__ import annotations

from dataclasses import dataclass, field

from webapp import __version__
from webapp.auth import Forbidden, Unauthorized, User, authenticate, require_role
from webapp.report import export_report
from webapp.store import Store

USERS = [
    User("alice", "admin", "tok-alice-0000000000"),
    User("bob", "member", "tok-bob-11111111111"),
]


@dataclass
class Response:
    status: int
    body: dict[str, object] = field(default_factory=dict)


def handle(method: str, path: str, headers: dict[str, str], store: Store) -> Response:
    try:
        if path == "/health":
            return Response(200, {"ok": True, "version": __version__})
        if path == "/version":
            return Response(200, {"version": __version__})
        user = authenticate(headers, USERS)
        if method == "GET" and path == "/profile":
            return Response(200, {"name": user.name, "role": user.role})
        if method == "GET" and path == "/admin/users":
            require_role(user, "admin")
            return Response(200, {"users": [u.name for u in USERS]})
        if method == "POST" and path.startswith("/admin/export/"):
            require_role(user, "admin")
            name = path.rsplit("/", 1)[-1]
            return Response(200, {"archive": export_report(name, store)})
        return Response(404, {"error": "not found"})
    except Unauthorized as exc:
        return Response(401, {"error": str(exc)})
    except Forbidden as exc:
        return Response(403, {"error": str(exc)})
