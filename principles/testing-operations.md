# Testing and operations

## Local and CI matrix

- Start an ephemeral local Worker and migrated D1 database with disposable keys.
- Test fresh schema and upgrades from each supported migration state.
- Run desktop-client contract tests against localhost using only test fixtures.
- Cover activate, repeat activate, validate, deactivate, expiry, revocation,
  refund, renewal, device reset/revive, platform slots, key transfer, malformed
  input, tampering, replay, clock boundaries, rate limits, timeouts, retries,
  concurrent claims, server restarts, and signing-key rotation.
- Property/fuzz test parsers, canonicalization, keys, and token payload boundaries.
- Assert that test bypasses and private fixture material cannot enter release
  configuration or artifacts.

## Observability and incident safety

- Measure route latency/status, D1 operations, rate-limit decisions, signature
  failures, replay attempts, device-slot conflicts, and key lifecycle events with
  bounded cardinality.
- Redact secrets, raw keys, signatures/tokens, authorization headers, request
  bodies, email, and raw device facts.
- Define alerts, dependency failure behavior, key compromise rotation, migration
  repair, backup/restore checks, and audit retention.
- Deployment uses least-privilege credentials, pinned actions/dependencies, an
  environment promotion process, health/smoke checks, and a rollback decision.

## Local quality gates

```text
npm ci
npm run typecheck
npm test
```

Run Worker/D1 integration and desktop localhost contract tests whenever routes,
schemas, crypto, guard logic, or error contracts change.

