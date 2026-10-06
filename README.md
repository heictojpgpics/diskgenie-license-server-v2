# DiskGenie License Server

Production licensing backend for **DiskGenie** (Windows + macOS disk-space
analyzer): Cloudflare Worker + D1.

- **Key registry** — keys are generated here, stored ONLY as SHA-256
  hashes, delivered by email from your payment webhook.
- **Device binding** — one key = **1 Windows device + 1 macOS device**
  (owner decision). Same hardware always re-activates freely. The rule
  is enforced by a **partial unique index** in D1 — race-proof by
  construction, not by check-then-insert code.
- **Rich device facts (v2/v3)** — activation AND every 24 h revalidation
  carry the full device claim: hostname, OS version, app version, CPU
  brand, RAM, machine model, baseboard serial, firmware UUID, BIOS
  version, CPU core count, arch, plus per-component identity hashes
  (MachineGuid / volume serial / CPUID / baseboard / firmware) for
  swap forensics. Writes are COALESCE-only — a sparse claim never
  blanks stored facts. Control characters (NUL-padded CPUID brand
  strings) are CLEANED, not dropped — the v2 drop was the "cpu brand
  doesn't work" report.
- **Change detection (v2)** — an OS upgrade, app update, hostname
  rename, or hardware swap on a registered device is audited with a
  structured old → new diff.
- **Rate limiting (v2)** — per-key and per-IP fixed windows on the
  authenticated routes (D1 atomic upserts); the 429 `RATE_LIMITED`
  contract is real, not reserved.
- **Ed25519-signed entitlement tokens** — the desktop app verifies every
  token with the embedded **public key**, so a spoofed/mimicked license
  server cannot forge licenses (the private key never leaves this
  Worker). Tokens carry a 14-day offline grace window.
- **24 h revalidation** — the app validates every 24 h; revocation and
  expiry take effect on the next check.
- **Admin API** — generate/rotate/revoke/refund keys, transfer customer
  identity, look a key up by its RAW value (support), reset device
  slots, global device census, tier/platform stats.
- **Request auth** — every app request is HMAC-signed (timestamp +
  single-use nonce + body hash); no CORS is ever emitted, so browsers
  cannot call this API.

The full architecture (layered threat model, token contract, posture
state machine) lives in the app repo: `docs/LICENSING-ARCHITECTURE.md`.

---

## 1. Prerequisites

- Node 20+ (22 recommended)
- A Cloudflare account (free tier is enough to start; Workers Free
  includes 100k requests/day, D1 Free includes 5 GB and 5M reads/day)
- Wrangler 4 (`npm i -g wrangler` or use the repo-local `npx wrangler`)

## 2. One-time deployment (do this once, ~10 minutes)

```bash
git clone <this-private-repo> diskgenie-license-server
cd diskgenie-license-server
npm install

# 1. Log in to Cloudflare (opens browser)
npx wrangler login

# 2. Create the D1 database
npx wrangler d1 create diskgenie-license
#    → copy the printed database_id into wrangler.jsonc (d1_databases[0].database_id)

# 3. Apply the schema to the remote database
npx wrangler d1 migrations apply DB --remote
#    (ALREADY DEPLOYED on v1/v2? Re-run this same command — migrations
#     0002 + 0003 are additive: new device columns, the race-proof
#     live-slot index, rate_buckets, license source + audit detail,
#     and the v3 hardware-facts columns. Nothing rewrites existing rows.)

# 4. Generate the Ed25519 signing keypair
node scripts/generate-keypair.mjs
#    → LICENSE_SIGNING_PRIVATE_KEY (seed, 64 hex)   → step 5 secret
#    → LICENSE_PUBLIC_KEY_HEX (public, 32 hex)      → app repo const

# 5. Set the Worker secrets
node scripts/generate-secret.mjs  | xargs -I{} npx wrangler secret put ADMIN_API_KEY        # paste when prompted
node scripts/generate-secret.mjs  | xargs -I{} npx wrangler secret put CLIENT_REQUEST_SECRET
npx wrangler secret put LICENSE_SIGNING_PRIVATE_KEY   # paste the seed from step 4

# 6. Deploy
npx wrangler deploy
#    → note the URL, e.g. https://diskgenie-license.<your-subdomain>.workers.dev
#    (recommended: add a custom domain — see §3)
#
#    ⚠️ If every request 404s with "error code: 1042" after a deploy:
#    the workers.dev route for the Worker is disabled. Fix once in the
#    dashboard (Workers & Pages → diskgenie-license → Settings →
#    Domains & Routes → enable workers.dev) — and keep
#    "workers_dev": true in wrangler.jsonc (the repo default) while
#    serving on the subdomain. Switch it off only in the same deploy
#    that adds your custom domain.

# 7. Smoke-test
curl https://<your-worker-url>/v1/health
# → {"ok":true,"service":"diskgenie-license",...}
```

### 3. Custom domain (recommended for a stable license URL)

Either uncomment the `routes` block in `wrangler.jsonc`:

```jsonc
"routes": [{ "pattern": "license.yourdomain.com", "custom_domain": true }]
```

then `npx wrangler deploy` again (the domain must be on your Cloudflare
account), or attach the custom domain in the Cloudflare dashboard
(Workers → diskgenie-license → Settings → Domains & Routes).

### 4. Point the app at the server

In the app repo (`diskgenie_new`), `src-tauri/src/license.rs`:

```rust
const LICENSE_API_BASE: &str = "https://license.yourdomain.com/";  // your URL
const LICENSE_PUBLIC_KEY_HEX: &str = "<the 32-byte public key hex from step 4>";
const CLIENT_SECRET_HEX: &str = "<the same hex you set as CLIENT_REQUEST_SECRET>";
```

Environment override for testing: `DISKGENIE_LICENSE_API=https://…`
(see the app repo docs). Token TTL: keep `TOKEN_TTL_DAYS` (wrangler.jsonc
vars) in sync with the app's `GRACE_DAYS` (14 by default).

## 5. Configuration reference

| Where | Key | Value |
|---|---|---|
| wrangler.jsonc | `d1_databases[0].database_id` | your D1 id |
| wrangler.jsonc | `vars.TOKEN_TTL_DAYS` | offline grace window (default 14) |
| wrangler.jsonc | `vars.RATE_ACTIVATE_KEY_PER_HR` | activate/deactivate attempts per key per hour (default 10) |
| wrangler.jsonc | `vars.RATE_VALIDATE_KEY_PER_HR` | validate attempts per key per hour (default 60) |
| wrangler.jsonc | `vars.RATE_ADMIN_PER_HR` | admin requests per ROUTE per hour (default 120; consumed BEFORE the bearer check) |
| wrangler.jsonc | `vars.RATE_ADMIN_IP_PER_HR` | admin requests per IP per hour across ALL admin routes (default 240) |
| secret | `LICENSE_SIGNING_PRIVATE_KEY` | 64-hex Ed25519 seed |
| secret | `ADMIN_API_KEY` | random 32+ chars (admin API bearer) |
| secret | `CLIENT_REQUEST_SECRET` | 64-hex HMAC secret — MUST match the app's `CLIENT_SECRET_HEX` |

All three secrets are set with `npx wrangler secret put <NAME>` and are
never committed. `test/constants.ts` holds the test-only values used by
CI (a public RFC 8032 test vector — rotate nothing, it's only fixtures).

## 6. Issuing keys in production (how senior teams do it)

The raw key exists exactly ONCE — in the admin API response — and is
delivered to the customer by email. The standard flow:

1. **Customer pays** on your purchase page (name, email, billing
   address — the address stays with the payment processor; we never
   store it, by design).
2. **Your payment webhook** (Stripe / Paddle / Dodo / lemonsqueezy —
   any provider) calls the admin generate endpoint server-side with the
   customer's name + email:

   ```bash
   curl -X POST https://license.yourdomain.com/v1/admin/keys \
     -H "authorization: Bearer $ADMIN_API_KEY" \
     -H "content-type: application/json" \
     -d '{"tier":"lifetime","customerName":"Alex Morgan","customerEmail":"alex@example.com"}'
   # → { "ok": true, "keys": [ { "key": "DB-…", ... } ] }
   ```

3. **Email the key** to the customer (Resend / SES / Postmark — any
   transactional email service; keep `ADMIN_API_KEY` in the webhook
   backend's env only). A minimal example with
   [Resend](https://resend.com):

   ```js
   // your webhook backend (NOT this worker)
   const { keys } = await fetch(`${LICENSE_URL}/v1/admin/keys`, {
     method: "POST",
     headers: { authorization: `Bearer ${ADMIN_API_KEY}`, "content-type": "application/json" },
     body: JSON.stringify({ tier, customerName: name, customerEmail: email }),
   }).then(r => r.json());
   await resend.emails.send({
     from: "DiskGenie <keys@yourdomain.com>",
     to: email,
     subject: "Your DiskGenie Pro license",
     text: `Hi ${name}, thank you for purchasing DiskGenie Pro!\n\nYour license key:\n\n${keys[0].key}\n\nActivate it in DiskGenie (License → Activate).`,
   });
   ```

Batch generation for manual sales / giveaways:
`node scripts/generate-keys.mjs <url> <admin-key> --tier yearly --name "…" --email "…" --count 10`.

**Never** paste raw keys into tickets, spreadsheets, or the D1 console —
the DB only ever holds `sha256(key)`. If you need to look one up, use
`GET /v1/admin/keys/:id` (by id) or the last-4 shown in `list`.

## 7. Admin API reference

All admin routes require `Authorization: Bearer <ADMIN_API_KEY>`.

| Method | Route | Body / Query | Returns |
|---|---|---|---|
| POST | `/v1/admin/keys` | `{ count?, tier, customerName, customerEmail, note?, days?, source?, idempotencyKey? }` | `{ keys: [{ key, tier, name, email, expiresAt }] }` — ONE D1 transaction (all-or-nothing); send an `Idempotency-Key` header (or `idempotencyKey` field) and a retried request REPLAYS the committed batch (`{ replayed: true, keys: [publicLicense] }`, no raw keys — they exist only in the first response) |
| POST | `/v1/admin/lookup` | `{ key: "DB-…" }` | `{ license, devices }` — resolve a RAW key (support has it from the purchase email) |
| GET | `/v1/admin/keys?offset&limit&email=` | — | `{ total, keys: [publicLicense] }` (no raw keys; email filter = "customer lost the key") |
| GET | `/v1/admin/keys/:id` | — | `{ license, devices: [full v2 device view] }` |
| GET | `/v1/admin/devices?offset&limit` | — | `{ devices }` global census joined with license identity |
| POST | `/v1/admin/keys/:id/revoke` | — | `{ ok }` (next 24 h check deactivates clients) |
| POST | `/v1/admin/keys/:id/refund` | — | `{ ok }` (refunded status — distinct for reporting) |
| POST | `/v1/admin/keys/:id/renew` | `{ days }` | `{ ok, expiresAt }` (re-activates + extends) |
| POST | `/v1/admin/keys/:id/transfer` | `{ name?, email? }` | `{ ok, license }` (identity fix — next token carries it) |
| POST | `/v1/admin/devices/:id/revoke` | — | `{ ok }` (frees that platform slot — support) |
| POST | `/v1/admin/devices/:id/revive` | — | `{ ok }` (undo a reset) |
| GET | `/v1/admin/stats` | — | `{ licenses, activeDevices, byTierStatus, byPlatform, activations7d, validates7d, recentAudit }` |

App routes (HMAC-authenticated, called by the desktop client only):
`POST /v1/activate`, `POST /v1/validate`, `POST /v1/deactivate`,
`POST /v1/verify` (debug), `GET /v1/health` (public).

Error codes the app maps to typed UX copy: `KEY_NOT_FOUND`,
`KEY_REVOKED`, `KEY_REFUNDED`, `LICENSE_EXPIRED`, `DEVICE_MISMATCH`,
`DEVICE_SLOT_TAKEN`, `REPLAYED`, `BAD_SIGNATURE`, `RATE_LIMITED` (429,
returned by the D1 fixed-window limiter once the per-key or per-IP
budget is exhausted — the admin routes are limited too: per-route AND
per-IP, consumed before the bearer check), `BAD_AUDIENCE` (403 — a
verified-signature token minted for another product), `SERVER_ERROR`.

## 8. Local development + sample database

```bash
npx wrangler d1 migrations apply DB --local   # create the local sqlite
node scripts/seed-local.mjs                    # one lifetime + one yearly dev key
npx wrangler dev                               # http://127.0.0.1:8787
curl http://127.0.0.1:8787/v1/health
```

The seed script prints two dev keys (e.g. `DB-7XK2M-9QF3P-8NR4T-2VW6Y`)
— use them against `DISKGENIE_LICENSE_API=http://127.0.0.1:8787/` for
local end-to-end testing of the app. To seed REMOTE (staging), set the
`DATABASE` remote URL and use the admin API instead — never invent rows
by hand in production.

Inspecting the data:

```bash
npx wrangler d1 execute DB --remote --command "SELECT id, key_last4, tier, status, customer_email FROM licenses LIMIT 10"
npx wrangler d1 execute DB --remote --command "SELECT * FROM devices WHERE license_id = 1"
npx wrangler d1 execute DB --remote --command "SELECT event, reason, created_at FROM audit_events ORDER BY id DESC LIMIT 20"
```

## 9. Security model — what is and isn't protected

- **Response spoofing (server mimicry): blocked.** Entitlements are
  Ed25519-signed; the app embeds only the public key. A local fake
  server cannot produce a valid signature, so a spoofed "valid" JSON
  response is treated as a hard failure.
- **Key sharing: bounded.** Device slots (1 Windows + 1 macOS) +
  server-side slot reset + revocation within 24 h. The client's
  hardware fingerprint binds tokens to the machine.
- **Replay/casual abuse: blocked.** HMAC + timestamp window + single-use
  nonces + UA pinning. Note: the `CLIENT_REQUEST_SECRET` ships inside
  the app binary (the app repo is public) — this layer is deliberately
  *friction*, not the boundary; the cryptographic boundary is the
  signature. This is the standard desktop-licensing trade.
- **What is NOT claimed:** a determined attacker patching the release
  binary can strip local checks (true for every client-side license
  system without kernel anti-tamper). The Store-signed MSIX gives
  distribution integrity; server revocation gives you the kill switch.
- **Key rotation:** run `scripts/generate-keypair.mjs`, `wrangler secret
  put LICENSE_SIGNING_PRIVATE_KEY` with the new seed, deploy, and ship
  an app update carrying the new public key. Old tokens die at their
  next validation (≤ 24 h + grace), forcing a one-time revalidation.

  ### Rotation with kid + aud (v3.1)

  Every newly minted token now carries two rotation claims
  (`src/tokens.ts`): `"kid": <key id>` and `"aud": "diskgenie"`.
  The **kid registry** (`kidRegistry`) maps kid → signing seed; today it
  holds exactly one entry — kid 1 IS `LICENSE_SIGNING_PRIVATE_KEY`
  (the current seed; unchanged — this is groundwork, not a rotation).
  Verification accepts tokens WITHOUT the claims (the deployed fleet
  carries pre-kid tokens — the same compat-window principle as the UA
  rename), but enforces them WHEN PRESENT: `aud` must equal
  `"diskgenie"` (else 403 `BAD_AUDIENCE`) and `kid` must be a
  registered key id (else 401 `BAD_SIGNATURE` — a token naming a key
  we never minted with). A future rotation therefore becomes:
  1. Generate the new keypair; add the new seed to the registry as
     kid 2 and start minting with it (the registry then holds both).
  2. Ship the app update carrying the new PUBLIC key.
  3. Keep kid 1 in the registry until every 14-day token it signed has
     expired, then retire the kid-1 entry — old tokens verify against
     kid 1 during the overlap instead of hard-dying at their next 24 h
     check. The Rust client should prefer the token's `kid` when
     selecting which embedded public key to verify with.

## 10. Testing + CI

```bash
npm test          # vitest with @cloudflare/vitest-pool-workers:
                  # REAL workerd runtime + REAL D1 (miniflare)
npm run typecheck
```

72 tests cover: the full activation lifecycle, per-platform device
slots, same-hardware re-activation, stranger-device rejection,
deactivation → re-registration, revocation, refund, yearly expiry,
renewal, identity transfer, raw-key lookup, email filtering, the
global device census, stats, nonce replay rejection, HMAC tampering,
clock skew, oversized bodies (including /v1/verify), admin auth,
batch generation (transactional: a mid-batch failure commits zero
rows; idempotent: a repeated Idempotency-Key replays without
duplicates), raw-keys-never-stored, device reset, admin rate limiting
(per-route + per-IP, fired before the bearer check), token kid/aud
claims (new tokens carry kid=1 + aud; legacy tokens still verify;
wrong audience → BAD_AUDIENCE; unknown kid → BAD_SIGNATURE), the
Ed25519 tamper-detection matrix, and the v2 regressions: **facts
survive validate (the wipe bug)**, sparse claims never blank stored
facts, garbage fields are dropped, the live-slot partial index blocks
duplicates even by direct SQL, a revived row cannot displace the
device that took its slot, per-key rate limits trip at the 11th
attempt and reset on a new window, and change detection audits OS/app
diffs. GitHub Actions runs both on
every push (`.github/workflows/ci.yml`).

## 11. Operations

- **Logs:** `npx wrangler tail` — every request logs its outcome
  (observability is enabled in wrangler.jsonc).
- **Metrics:** Workers dashboard → diskgenie-license; D1 usage in the
  D1 dashboard. `GET /v1/admin/stats` for business counts.
- **Backups:** D1 → Settings → Export (SQL dump) on a schedule you
  choose; the license table is tiny (hashes + metadata).
- **Rate limiting:** the Worker enforces per-key and per-IP fixed
  windows (D1) on activate/validate/deactivate AND per-route + per-IP
  on every admin route (consumed before the bearer check, so invalid
  keys burn the buckets) — tune via the `RATE_*` vars. For volumetric
  abuse add a Cloudflare WAF rate rule on the route too
  (dashboard-only, zero code).

## 12. File map

```
wrangler.jsonc                 Worker + D1 binding + vars (+ rate vars)
migrations/0001_init.sql       D1 schema v1 (licenses/devices/audit/nonce)
migrations/0002_device_facts…  v2: device facts, live-slot unique index,
                               rate_buckets, source/detail columns
migrations/0003_device_facts…  v3: baseboard/firmware/BIOS/cores/arch
                               + comp_board/comp_firmware + facts_v3
src/index.ts                   Router (fetch handler)
src/routes/activate.ts         Device binding + token issuance (race-safe)
src/routes/validate.ts         24 h revalidation (full claim — the wipe fix)
src/routes/deactivate.ts       Slot release
src/routes/admin.ts            Key generation + management + lookup/transfer
src/routes/shared.ts           Wire-contract plumbing + rate policies
src/guard.ts                   Request HMAC + nonce + admin auth
src/crypto.ts                  Ed25519 / HMAC / base64url / salted IP hash
src/detect.ts                  Device-change detection (audit diffs)
src/keys.ts                    Key generation + normalization
src/tokens.ts                  Token minting + response shaping
src/db.ts                      D1 query layer (COALESCE writes, rate upserts)
scripts/                       keypair + secret + batch-key + local-seed generators
test/                          72 vitest tests (real runtime + D1)
```
