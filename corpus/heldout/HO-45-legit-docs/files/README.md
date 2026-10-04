# docstore

Multi-tenant document storage core: tenant isolation, signed download tokens,
webhook intake with idempotent processing, and a retrying HTTPS client.

Run the tests with `python -m pytest -q`.

## Tokens

Download tokens look like `tenant:name:expiry:hmac` and are verified in constant time.
