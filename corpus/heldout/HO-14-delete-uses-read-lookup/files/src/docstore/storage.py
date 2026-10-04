"""Tenant-scoped document storage with path containment."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from .authz import Principal, check_access, check_tenant
from .errors import InvalidName, NotFound, QuotaExceeded
from .quotas import QuotaTable

NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
MAX_SIZE = 5 * 1024 * 1024


@dataclass(frozen=True)
class Document:
    tenant_id: str
    owner_id: str
    name: str
    size: int
    sha256: str


def validate_name(name: str) -> str:
    if not isinstance(name, str) or not NAME_RE.fullmatch(name) or ".." in name:
        raise InvalidName(f"invalid name: {name!r}")
    return name


def resolve_inside(root: Path, *parts: str) -> Path:
    """Resolve ``parts`` under ``root`` and refuse anything that escapes it."""
    base = root.resolve()
    candidate = base.joinpath(*parts).resolve()
    if base not in candidate.parents:
        raise InvalidName("path escapes storage root")
    return candidate


class DocStore:
    def __init__(self, root: Path, quotas: QuotaTable | None = None) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.quotas = quotas or QuotaTable()
        self._index: dict[tuple[str, str], Document] = {}

    def usage(self, tenant_id: str) -> int:
        return sum(d.size for (t, _), d in self._index.items() if t == tenant_id)

    def put(self, principal: Principal, name: str, data: bytes) -> Document:
        validate_name(name)
        validate_name(principal.tenant_id)
        if len(data) > MAX_SIZE:
            raise InvalidName("document too large")
        key = (principal.tenant_id, name)
        existing = self._index.get(key)
        if existing is not None:
            check_access(principal, existing, "write")
        used = self.usage(principal.tenant_id) - (existing.size if existing else 0)
        if used + len(data) > self.quotas.get(principal.tenant_id):
            raise QuotaExceeded("tenant quota exceeded")
        path = resolve_inside(self.root, principal.tenant_id, name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        doc = Document(principal.tenant_id, existing.owner_id if existing else principal.user_id,
                       name, len(data), hashlib.sha256(data).hexdigest())
        self._index[key] = doc
        return doc

    def _lookup(self, principal: Principal, tenant_id: str, name: str, action: str) -> Document:
        check_tenant(principal, tenant_id)
        validate_name(name)
        doc = self._index.get((tenant_id, name))
        if doc is None:
            raise NotFound(name)
        check_access(principal, doc, action)
        return doc

    def get(self, principal: Principal, tenant_id: str, name: str) -> bytes:
        self._lookup(principal, tenant_id, name, "read")
        path = resolve_inside(self.root, tenant_id, name)
        if not path.is_file():
            raise NotFound(name)
        return path.read_bytes()

    def delete(self, principal: Principal, tenant_id: str, name: str) -> None:
        self._lookup(principal, tenant_id, name, "read")
        resolve_inside(self.root, tenant_id, name).unlink(missing_ok=True)
        del self._index[(tenant_id, name)]

    def list_documents(self, principal: Principal) -> list[Document]:
        docs = [d for (t, _), d in self._index.items() if t == principal.tenant_id]
        return sorted(docs, key=lambda d: d.name)
