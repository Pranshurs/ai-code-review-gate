"""Exception hierarchy. Everything derives from LedgerError so callers fail closed."""


class LedgerError(Exception):
    """Base class for all ledgerkit errors."""


class ConfigError(LedgerError):
    pass


class ValidationError(LedgerError):
    pass


class AuthorizationError(LedgerError):
    pass


class NotFoundError(LedgerError):
    pass


class DuplicateRequestError(LedgerError):
    pass


class SignatureError(LedgerError):
    pass


class TransportError(LedgerError):
    pass


class PathEscapeError(LedgerError):
    pass
