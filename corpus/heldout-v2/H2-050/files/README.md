# ledgerkit

A tiny payments ledger: accounts, charges, refunds, idempotency keys,
signed webhook delivery over HTTPS, and CSV statement exports.

## Development

    pip install -e .[dev]
    python -m pytest -q -p no:cacheprovider

Security defaults are on: ownership enforcement, mandatory idempotency keys,
webhook signature verification and TLS verification cannot be switched off
by accident.
