# Worklog

## 2026-10-05 — bootstrap

- Created and pushed the `diskgenie-license-server-v2` repository while retaining
  the original as `upstream`.
- Added cross-linked production security, protocol, testing, and operations
  principles before implementation changes.

## 2026-10-05 — baseline and replay hardening

- Audited request authentication, nonce handling, token claims, device-slot
  enforcement, administrative operations, and CI coverage alongside the app.
- Found that activation, validation, and deactivation consumed single-use
  nonces, while the authenticated `/v1/verify` debug endpoint did not.
- Added atomic nonce consumption to `/v1/verify` and an end-to-end replay test
  using the real Worker, Miniflare D1, and request-signing contract.
- Local post-change gates passed: TypeScript typecheck and 59 tests across five
  files. Token key rotation, product/audience claims, transactional admin batch
  operations, and local-server app integration remain prioritized follow-ups.
