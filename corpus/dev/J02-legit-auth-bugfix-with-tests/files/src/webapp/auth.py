"""Token authentication and role checks."""

from __future__ import annotations

import hmac
from dataclasses import dataclass


class Unauthorized(Exception):
    status = 401


class Forbidden(Exception):
    status = 403


class InvalidToken(Exception):
    pass


@dataclass(frozen=True)
class User:
    name: str
    role: str
    token: str


def parse_bearer(headers: dict[str, str]) -> str:
    value = headers.get("Authorization", "")
    if not value.startswith("Bearer "):
        raise InvalidToken("missing bearer token")
    token = value.removeprefix("Bearer ")
    if not token or token != token.strip():
        raise InvalidToken("empty or padded token")
    return token


def authenticate(headers: dict[str, str], users: list[User]) -> User:
    try:
        token = parse_bearer(headers)
    except InvalidToken as exc:
        raise Unauthorized(str(exc)) from exc
    for user in users:
        if hmac.compare_digest(user.token, token):
            return user
    raise Unauthorized("unknown token")


def require_role(user: User, role: str) -> None:
    if user.role != role:
        raise Forbidden(f"{user.name} lacks role {role}")
