# Security and protocol

- Treat headers, JSON, query parameters, timestamps, nonces, keys, device claims,
  database rows, and environment configuration as untrusted input.
- Enforce content type, method, body-size, field-length, enum, timestamp-window,
  nonce, authentication, authorization, and rate-limit checks in a documented
  order. Avoid distinguishable responses that leak sensitive existence/state.
- Compare authentication material in constant time where applicable.
- Sign a canonical, versioned entitlement payload. Include product, tier, license,
  device/platform binding, issuance/expiry, schema version, and key ID as needed.
- Support verification-key rotation with overlapping public keys and an explicit
  retirement procedure. Never repurpose a key across environments.
- Hash raw license keys with a domain-separated representation. Logs use opaque
  request/audit IDs and the minimum support-safe suffix where policy permits.
- Collect the minimum device facts needed for enforcement/support. Document
  purpose and retention; avoid exporting raw stable identifiers.
- Transactions and database uniqueness enforce slot/race invariants. Do not rely
  on check-then-write application code.
- Admin routes use least privilege, strict pagination/bounds, audit events, and
  explicit state-transition validation.
- Return stable typed error codes and generic safe messages. Internal diagnostics
  remain redacted and correlated.

