# DiskGenie license-server principles

This service is a security and availability boundary. Correct authorization,
privacy, auditability, schema compatibility, and safe failure outrank convenience.

## Required documents

- [Security and protocol](principles/security-protocol.md)
- [Testing and operations](principles/testing-operations.md)
- The app repository's `PRINCIPLES.md` and `principles/09-licensing.md` for the
  shared client/server state model

## Non-negotiable rules

1. Version schemas and error codes; coordinate client/server rollout.
2. Validate and bound every request before database or cryptographic work.
3. Store only key hashes; return a raw generated key only at the documented
   issuance boundary and never log it.
4. Signing private keys, admin credentials, HMAC secrets, and production data
   never enter source, test artifacts, screenshots, or logs.
5. Make mutations transactional/idempotent where retries or races can occur.
6. Signed entitlement verification is the security boundary; a shared desktop
   HMAC secret is abuse friction and must not be represented as unextractable.
7. Database migrations are forward-safe, tested from every supported prior
   schema, and paired with rollback/repair guidance.
8. Rate limiting, nonce replay protection, clock windows, device slots, expiry,
   revocation, and rotation have deterministic tests under concurrency.
9. CI uses ephemeral local Worker/D1 state and disposable test keys.
10. Run local type/tests and a redaction check before push.

