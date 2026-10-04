# Security model

- Every operation checks that the principal owns the account.
- Mutating calls require an idempotency key; keys are scoped per principal.
- Webhooks are signed with HMAC-SHA256 and verified with a constant-time compare.
- Webhook delivery is HTTPS only and uses the default TLS context.
- Exports are confined to the configured export root.
