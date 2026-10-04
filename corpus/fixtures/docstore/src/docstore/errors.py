"""Exception hierarchy. Every failure path raises one of these (fail closed)."""


class DocStoreError(Exception):
    """Base class for all docstore errors."""


class AccessDenied(DocStoreError):
    """The principal is not allowed to perform the action."""


class InvalidName(DocStoreError):
    """A tenant or document name failed validation."""


class NotFound(DocStoreError):
    """The requested document does not exist."""


class QuotaExceeded(DocStoreError):
    """The tenant would exceed its storage quota."""


class InvalidToken(DocStoreError):
    """A signed token or webhook signature is invalid."""


class InvalidEvent(DocStoreError):
    """A webhook event is malformed or of an unknown type."""


class ToolError(DocStoreError):
    """An external helper program failed."""


class UpstreamError(DocStoreError):
    """The upstream HTTPS service failed or refused the request."""
