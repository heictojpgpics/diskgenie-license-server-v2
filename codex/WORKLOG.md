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

## 2026-10-06 — hardening: transactional admin batches, verify hardening, admin rate limits, token kid/aud

All four changes below landed with the full local gates green after EACH step
(`npm run typecheck` + `npm test`, real workerd + D1). Suite: 59 → 72 tests
(+13, no existing test removed; intent preserved everywhere).

### 1. Transactional + idempotent admin batch generation (src/routes/admin.ts, src/db.ts)

- `POST /v1/admin/keys` now writes the whole generation + its audit row in
  ONE `db.batch()` call (`insertLicensesAtomic`) — a D1 implicit transaction.
  Previously the per-key loop committed each insert separately, so a mid-loop
  failure (D1 blip, constraint) left earlier keys committed while their raw
  values were already lost to the caller: only hashes persist, so those keys
  were unrecoverable. All-or-nothing is the only safe shape for a one-shot
  reveal. The old per-key 5-attempt hash-collision retry is preserved as a
  per-BATCH retry (fresh candidates each attempt, in-batch duplicates
  pre-filtered).
- Idempotency for webhook retries: optional `Idempotency-Key` header (or
  `idempotencyKey` body field, ≤ 200 chars). The batch is recorded under the
  marker `idem:<sha256(key)>` in `licenses.source`; a repeated request
  replays the committed rows (`{ ok: true, replayed: true, keys:
  [publicLicense] }`) without minting duplicates. Documented tradeoff (code
  comment + README §7): raw keys exist only in the FIRST response — the
  caller must persist them; replays return the publicLicense view only.
  When no idempotency key is sent, `source` keeps its webhook/seed/admin tag
  exactly as before (the "generate stores the source tag" test still passes
  unchanged).
- Tests (+4): count-correctness positive path; a mid-batch DB failure commits
  ZERO rows (proved end-to-end by wrapping `env.DB.batch` and splicing a
  colliding INSERT after the route's first statement — also pins that D1
  `batch()` really is transactional in workerd); same Idempotency-Key replays
  the same rows (no duplicates, no raw keys, different key → fresh batch);
  body-field variant.
- Test-helper note: `admin()` in api.test.ts had a latent spread-order bug
  (`{ headers: {...}, ...init }` let `init.headers` DROP the bearer header);
  fixed to merge — intent preserved, existing callers unaffected.

### 2. /v1/verify hardening (src/index.ts, src/routes/shared.ts)

- Body-size guard: exported `MAX_BODY_BYTES` from shared.ts and applied it
  BEFORE the HMAC guard (same order as the app routes' `verifyAndParse`).
- Malformed JSON body now returns 400 BAD_REQUEST (previously escaped to the
  outer catch as 500 SERVER_ERROR — a client bug is not a server fault).
- Public-key derivation memoized per isolate (module-level cache keyed on
  the seed, same pattern as crypto.ts's IP-salt memo) instead of re-deriving
  the Ed25519 key on every call.
- Nonce consumption and the both-UA compat window are untouched (pinned by
  the existing replay + rename tests, both still green).
- Tests (+2): oversized /v1/verify body → 400; signed-but-invalid JSON → 400
  (not 500).

### 3. Admin rate limiting (src/routes/admin.ts, src/types.ts, wrangler.jsonc)

- The admin surface had NO rate limit behind the bearer check — an
  unlimited brute-force oracle on ADMIN_API_KEY. Every /v1/admin/* request
  now consumes two fixed-window buckets on the SAME `rate_buckets`
  mechanism as the app routes, BEFORE the bearer check (invalid keys burn
  them — the brute-forcer is exactly who the limit is for):
  - per ROUTE (`rl:admin:<METHOD route-shape>`, ids normalized to `:id`):
    `RATE_ADMIN_PER_HR` (default 120) — bounds any single operation
    globally (runaway webhook retry loops);
  - per IP (`rl:admin:ip:<ipHash>`): `RATE_ADMIN_IP_PER_HR` (default 240) —
    bounds each source across ALL admin routes.
  Both vars added to wrangler.jsonc + the Env type; 429s use the app
  routes' RATE_LIMITED error body shape and are audited (`denied`).
- Design note (deviation, documented): the spec named the two vars without
  fully pinning their bucket semantics; per-route + per-IP is the reading
  that makes both limits meaningful (a single per-IP limit would leave
  `RATE_ADMIN_PER_HR` unused).
- Tests (+3): hammering past the per-route limit → 429 (with the shared
  error body); the limit fires BEFORE the bearer check (wrong key → 429,
  not 401; valid key also refused in the same window); the per-IP bucket
  spans all admin routes.

### 4. Token kid + aud (src/tokens.ts, src/types.ts, src/guard.ts, src/index.ts)

- Newly minted tokens carry `"kid": 1` and `"aud": "diskgenie"`
  (mintToken payload assembly). The seed and the Ed25519 signature scheme
  are UNCHANGED; the UA compat window is untouched.
- `KID_REGISTRY` (`kidRegistry(env)` in tokens.ts): `{ 1:
  LICENSE_SIGNING_PRIVATE_KEY }` — the current seed is kid 1.
- Verification (/v1/verify via `checkTokenClaims`) accepts tokens WITHOUT
  kid/aud (the deployed fleet's compat window) but enforces them WHEN
  PRESENT: `aud` must equal "diskgenie" → else 403 with the new
  `BAD_AUDIENCE` code (added to the GuardFailure union + GUARD_STATUS);
  `kid` must be a registered key id → else 401 BAD_SIGNATURE (a token
  naming a key we never minted with is a signature-level failure — the
  spec left this code open; BAD_AUDIENCE got its dedicated code, kid did
  not).
- README §9 rewritten: rotation now describes the kid registry + aud claim
  and the kid-2 overlap procedure.
- Tests (+4 net): new tokens carry kid=1 + aud (extended the existing
  activation-contract test); legacy token (minted manually without kid/aud)
  still verifies; aud "other-product" → 403 BAD_AUDIENCE; unknown kid → 401
  BAD_SIGNATURE; manual kid=1/aud=diskgenie token verifies.

### Docs

- README: §5 config table (the two new vars), §7 admin reference
  (idempotency contract) + error-code list (BAD_AUDIENCE, admin limits),
  §9 rotation (kid registry + aud), §10/§12 test counts (72).
- wrangler.jsonc vars + rationale comments.

Gates after everything: `npm run typecheck` clean; `npm test` 72/72 across
5 files (api 30, api2 30, schema 2, crypto 5, keys 5).
