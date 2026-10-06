/**
 * Admin API (`/v1/admin/*`, `Authorization: Bearer ADMIN_API_KEY`).
 *
 * This is the ONLY place license keys are created — the production
 * pattern (README §6): your payment provider's webhook (or a trusted
 * operator) calls POST /v1/admin/keys after payment, receives the raw
 * keys ONCE, and emails them to the customer. Raw keys are never
 * stored.
 *
 * Rate limiting (v3.1): every /v1/admin/* request consumes a per-route
 * and a per-IP fixed-window bucket BEFORE the bearer check (invalid
 * keys burn them too — see checkAdminRate below).
 *
 * v2 additions:
 *   POST /v1/admin/lookup            { key } — resolve a RAW key the
 *                                     operator already has (purchase
 *                                     email) to its license + devices
 *   GET  /v1/admin/keys?email=…      — filter by customer email
 *   POST /v1/admin/keys/:id/transfer { name?, email } — identity fix
 *   POST /v1/admin/keys/:id/refund   — mark refunded (distinct from
 *                                     revoked for reporting)
 *   GET  /v1/admin/devices           — global device census
 *   GET  /v1/admin/stats             — per-tier/status + per-platform
 *                                     device counts + activation volume
 *
 * Routes (v1, unchanged contracts):
 *   POST /v1/admin/keys            { count?, tier, customerName, customerEmail, note?, days?, source?, idempotencyKey? }
 *                                  — also accepts an `Idempotency-Key` header:
 *                                    same key ⇒ the committed batch is REPLAYED
 *                                    (publicLicense view, `replayed: true`) with
 *                                    no duplicate rows; raw keys come back only
 *                                    on the FIRST request (they are never stored).
 *   GET  /v1/admin/keys?offset&limit[&email]
 *   GET  /v1/admin/keys/:id
 *   POST /v1/admin/keys/:id/revoke
 *   POST /v1/admin/keys/:id/renew  { days }
 *   POST /v1/admin/devices/:id/revoke     (frees a platform slot — support)
 *   POST /v1/admin/devices/:id/revive     (undo a device reset)
 */
import type { Env } from "../types";
import { Db, type DeviceRow, type LicenseInsert, type LicenseRow } from "../db";
import { generateKey, isValidKeyShape, normalizeKey } from "../keys";
import { keyHashOf } from "../tokens";
import { verifyAdmin } from "../guard";
import { ipHashOf, sha256Hex } from "../crypto";
import { fail, json, nowSec, normalizeKeyClaim, isValidPlatform } from "./shared";

const YEAR_DAYS = 365;

/** Idempotency keys are webhook-supplied opaque strings; anything past a
 *  sane length is abuse, not a retry marker. */
const MAX_IDEMPOTENCY_KEY = 200;

// ── admin rate limiting ────────────────────────────────────────────────
//
// The admin routes shipped (v1–v3) with NO rate limit behind the bearer
// check — an unlimited brute-force oracle on ADMIN_API_KEY, while every
// app route was already limited. Two fixed-window buckets on the SAME
// rate_buckets mechanism as the app routes, consumed BEFORE the bearer
// check so even INVALID keys burn them (the brute-forcer is the exact
// caller the limit exists for):
//   * per ROUTE  — RATE_ADMIN_PER_HR (default 120): bounds any single
//     admin operation globally (a runaway webhook retry loop can't
//     hammer one endpoint);
//   * per IP     — RATE_ADMIN_IP_PER_HR (default 240): bounds each
//     source across ALL admin routes.

const ADMIN_WINDOW_SEC = 3_600;
const ADMIN_ROUTE_LIMIT = 120;
const ADMIN_IP_LIMIT = 240;

/** Env-var override with the documented default (same semantics as
 *  keyLimitFor in shared.ts — absent/garbage falls back, never 0). */
const envLimit = (raw: string | undefined, fallback: number): number => {
  const n = Number.parseInt(raw ?? "", 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
};

/** The bucket id for one admin operation: method + route shape with
 *  numeric id segments normalized ("POST keys/:id/revoke"), so per-key
 *  operations share one bucket per SHAPE, not one per row id. */
function adminRouteId(method: string, parts: string[]): string {
  return [method.toUpperCase(), ...parts.map((p) => (/^\d+$/.test(p) ? ":id" : p))].join(" ");
}

/** Consume the admin buckets; returns the 429 Response when exhausted,
 *  null when the request may proceed. */
async function checkAdminRate(
  env: Env,
  db: Db,
  request: Request,
  parts: string[],
  now: number,
): Promise<Response | null> {
  const ipHash = await ipHashOf(env, request.headers.get("cf-connecting-ip"));
  const route = adminRouteId(request.method, parts);
  if (!(await db.rateConsume(`rl:admin:${route}`, envLimit(env.RATE_ADMIN_PER_HR, ADMIN_ROUTE_LIMIT), ADMIN_WINDOW_SEC, now))) {
    await db.audit({ event: "denied", reason: "RATE_LIMITED", ipHash, now });
    return fail(429, "RATE_LIMITED", "Too many admin requests — try again later.");
  }
  if (!(await db.rateConsume(`rl:admin:ip:${ipHash}`, envLimit(env.RATE_ADMIN_IP_PER_HR, ADMIN_IP_LIMIT), ADMIN_WINDOW_SEC, now))) {
    await db.audit({ event: "denied", reason: "RATE_LIMITED", ipHash, now });
    return fail(429, "RATE_LIMITED", "Too many admin requests from this network — try again later.");
  }
  return null;
}

interface GenerateBody {
  count?: number;
  tier?: string;
  customerName?: string;
  customerEmail?: string;
  note?: string;
  days?: number;
  source?: string;
  idempotencyKey?: string;
}

export async function handleAdmin(env: Env, request: Request, url: URL): Promise<Response> {
  const db = new Db(env.DB);
  const now = nowSec();
  const path = url.pathname.replace(/^\/v1\/admin\/?/, "").replace(/\/$/, "");
  const parts = path.split("/").filter(Boolean);

  // Rate limit FIRST — before the bearer check — so even invalid keys
  // burn the buckets (see the block above). The bearer check follows.
  const limited = await checkAdminRate(env, db, request, parts, now);
  if (limited) return limited;

  const adminFail = verifyAdmin(env, request);
  if (adminFail) return fail(401, adminFail, "Admin authentication failed.");

  // POST /v1/admin/keys — generate
  if (request.method === "POST" && parts.length === 1 && parts[0] === "keys") {
    let body: GenerateBody;
    try {
      body = (await request.json()) as GenerateBody;
    } catch {
      return fail(400, "BAD_REQUEST", "Malformed body.");
    }
    const count = Math.min(Math.max(Number(body.count ?? 1), 1), 500);
    const tier = body.tier === "yearly" || body.tier === "lifetime" ? body.tier : null;
    if (!tier) return fail(400, "BAD_REQUEST", "tier must be 'yearly' or 'lifetime'.");
    const name = (body.customerName ?? "").trim();
    const email = (body.customerEmail ?? "").trim();
    if (name.length < 1 || name.length > 120) return fail(400, "BAD_REQUEST", "customerName required (1-120 chars).");
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return fail(400, "BAD_REQUEST", "customerEmail must be a valid email.");
    const days = body.days ?? YEAR_DAYS;
    if (!Number.isFinite(days) || days < 1 || days > 3650) return fail(400, "BAD_REQUEST", "days must be 1-3650.");
    const expiresAt = tier === "yearly" ? now + days * 86_400 : null;

    // Idempotency (webhook at-least-once delivery): when the caller
    // supplies an Idempotency-Key header (or body field), the whole batch
    // is recorded under the marker `idem:<sha256(key)>` in licenses.source,
    // and a repeated request with the SAME key replays the already-
    // committed rows instead of minting duplicates. TRADEOFF: raw keys are
    // returned ONLY on the FIRST request (they are never stored), so the
    // replay returns the publicLicense view + `replayed: true` — the
    // caller must persist the raw keys from the first response. When no
    // idempotency key is supplied, `source` keeps its webhook/seed/admin
    // tag exactly as before.
    const idemRaw =
      request.headers.get("idempotency-key") ??
      (typeof body.idempotencyKey === "string" ? body.idempotencyKey : "");
    const idem = idemRaw.trim();
    if (idem.length > MAX_IDEMPOTENCY_KEY) {
      return fail(400, "BAD_REQUEST", "idempotencyKey too long (max 200 chars).");
    }
    const marker = idem.length > 0 ? `idem:${await sha256Hex(idem)}` : null;
    if (marker !== null) {
      const existing = await db.licensesBySource(marker);
      if (existing.length > 0) {
        await db.audit({ event: "admin", reason: `generate:replay:${existing.length}`, detail: marker, now });
        return json(200, { ok: true, replayed: true, keys: existing.map(publicLicense) });
      }
    }
    const source = marker ?? (body.source === "webhook" ? "webhook" : body.source === "seed" ? "seed" : "admin");

    // ONE D1 batch = one implicit transaction: the whole generation
    // commits or nothing does. (The previous per-key loop committed each
    // insert separately, so a mid-loop failure returned GEN_FAILED with
    // earlier keys already committed — their raw values lost forever,
    // since only hashes are stored. All-or-nothing is the only safe
    // shape for a one-shot reveal.)
    let generated: { key: string; tier: string; name: string; email: string; expiresAt: number | null }[] | null = null;
    for (let attempt = 0; attempt < 5 && generated === null; attempt++) {
      // Fresh candidate set per attempt — the (2^-50-scale) hash-collision
      // retry from the old per-key loop, now per BATCH: a collision with an
      // existing row fails the whole transaction (zero rows committed) and
      // we simply try again with new keys. In-batch duplicates are
      // pre-filtered so the UNIQUE constraint never fires against our own
      // set; shape guarantees uniqueness in practice.
      const candidates: string[] = [];
      const seen = new Set<string>();
      while (candidates.length < count) {
        const key = normalizeKey(generateKey());
        if (!isValidKeyShape(key) || seen.has(key)) continue;
        seen.add(key);
        candidates.push(key);
      }
      try {
        const rows: LicenseInsert[] = await Promise.all(
          candidates.map(async (key) => ({
            keyHash: await keyHashOf(key),
            keyLast4: key.slice(-4),
            tier,
            customerName: name,
            customerEmail: email,
            note: body.note ?? null,
            source,
            issuedAt: now,
            expiresAt,
            now,
          })),
        );
        // The audit row rides INSIDE the transaction — a half-committed
        // generation can never leave an audit trace without its keys (or
        // vice versa).
        await db.insertLicensesAtomic(rows, { event: "admin", reason: `generate:${tier}x${count}`, detail: source, now });
        generated = candidates.map((key) => ({ key, tier, name, email, expiresAt }));
      } catch {
        generated = null; // rolled back wholesale — safe to retry
      }
    }
    if (generated === null) return fail(500, "GEN_FAILED", "Key generation failed — retry.");
    return json(200, { ok: true, keys: generated });
  }

  // POST /v1/admin/lookup — resolve a RAW key (operator has it from the
  // purchase email) to license + devices. Same hash path as activate.
  if (request.method === "POST" && parts.length === 1 && parts[0] === "lookup") {
    let raw = "";
    try {
      const body = (await request.json()) as { key?: unknown };
      raw = normalizeKeyClaim(body.key);
    } catch {
      return fail(400, "BAD_REQUEST", "Malformed body.");
    }
    if (raw.length !== 22) return fail(400, "BAD_REQUEST", "Malformed license key.");
    const license = await db.licenseByHash(await keyHashOf(raw));
    if (!license) return fail(404, "NOT_FOUND", "No license for that key.");
    const devices = (await db.devicesOfLicense(license.id)).map(publicDevice);
    await db.audit({ licenseId: license.id, keyLast4: license.key_last4, event: "admin", reason: "lookup", now });
    return json(200, { ok: true, license: publicLicense(license), devices });
  }

  // GET /v1/admin/keys — paged list (no raw keys anywhere in the
  // response); optional email filter (support: "customer lost the key").
  if (request.method === "GET" && parts.length === 1 && parts[0] === "keys") {
    const offset = Math.max(Number(url.searchParams.get("offset") ?? 0) || 0, 0);
    const limit = Math.min(Math.max(Number(url.searchParams.get("limit") ?? 50) || 50, 1), 200);
    const email = url.searchParams.get("email")?.trim().toLowerCase() ?? "";
    const filter = email.length > 0 ? email : undefined;
    const rows = await db.licensesPage(offset, limit, filter);
    const total = await db.countLicenses(filter);
    return json(200, {
      ok: true,
      total,
      offset,
      limit,
      keys: rows.map(publicLicense),
    });
  }

  // GET /v1/admin/devices — global device census (newest first), each
  // row joined with its license identity (support: who owns this box).
  if (request.method === "GET" && parts.length === 1 && parts[0] === "devices") {
    const offset = Math.max(Number(url.searchParams.get("offset") ?? 0) || 0, 0);
    const limit = Math.min(Math.max(Number(url.searchParams.get("limit") ?? 50) || 50, 1), 200);
    const rows = await db.devicesWithLicense(offset, limit);
    return json(200, {
      ok: true,
      offset,
      limit,
      devices: rows.map((d) => ({
        ...publicDevice(d),
        keyLast4: d.key_last4,
        customerName: d.customer_name,
        customerEmail: d.customer_email,
        tier: d.tier,
      })),
    });
  }

  // GET /v1/admin/keys/:id
  if (request.method === "GET" && parts.length === 2 && parts[0] === "keys") {
    const id = Number(parts[1]);
    if (!Number.isInteger(id)) return fail(400, "BAD_REQUEST", "Bad id.");
    const row = await db.licenseById(id);
    if (!row) return fail(404, "NOT_FOUND", "No such license.");
    const devices = (await db.devicesOfLicense(id)).map(publicDevice);
    return json(200, { ok: true, license: publicLicense(row), devices });
  }

  // POST /v1/admin/keys/:id/revoke | renew | transfer | refund
  if (request.method === "POST" && parts.length === 3 && parts[0] === "keys") {
    const id = Number(parts[1]);
    const action = parts[2];
    if (!Number.isInteger(id)) return fail(400, "BAD_REQUEST", "Bad id.");
    const row = await db.licenseById(id);
    if (!row) return fail(404, "NOT_FOUND", "No such license.");
    if (action === "revoke") {
      await db.setLicenseStatus(id, "revoked", now);
      await db.audit({ licenseId: id, keyLast4: row.key_last4, event: "admin", reason: "revoke", now });
      return json(200, { ok: true });
    }
    if (action === "refund") {
      await db.setLicenseStatus(id, "refunded", now);
      await db.audit({ licenseId: id, keyLast4: row.key_last4, event: "admin", reason: "refund", now });
      return json(200, { ok: true });
    }
    if (action === "renew") {
      let days = 365;
      try {
        const body = (await request.json()) as { days?: number };
        days = Math.min(Math.max(Number(body?.days ?? 365), 1), 3650);
      } catch {
        // default 365
      }
      const base = Math.max(row.expires_at ?? row.issued_at, now);
      await db.extendLicenseExpiry(id, base + days * 86_400, now);
      await db.setLicenseStatus(id, "active", now);
      await db.audit({ licenseId: id, keyLast4: row.key_last4, event: "admin", reason: `renew:${days}d`, now });
      return json(200, { ok: true, expiresAt: base + days * 86_400 });
    }
    if (action === "transfer") {
      let name = row.customer_name;
      let email = row.customer_email;
      try {
        const body = (await request.json()) as { name?: unknown; email?: unknown };
        if (typeof body.name === "string" && body.name.trim().length >= 1 && body.name.trim().length <= 120) {
          name = body.name.trim();
        }
        if (typeof body.email === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email.trim())) {
          email = body.email.trim().toLowerCase();
        }
      } catch {
        // keep current identity
      }
      await db.transferLicense(id, name, email, now);
      await db.audit({ licenseId: id, keyLast4: row.key_last4, event: "admin", reason: "transfer", detail: JSON.stringify({ name, email }), now });
      return json(200, { ok: true, license: { ...publicLicense(row), customerName: name, customerEmail: email } });
    }
    return fail(404, "NOT_FOUND", "Unknown action.");
  }

  // POST /v1/admin/devices/:id/revoke | revive
  if (request.method === "POST" && parts.length === 3 && parts[0] === "devices") {
    const id = Number(parts[1]);
    const action = parts[2];
    if (!Number.isInteger(id)) return fail(400, "BAD_REQUEST", "Bad id.");
    const row = await db.deviceById(id);
    if (!row) return fail(404, "NOT_FOUND", "No such device.");
    if (action === "revoke") {
      await db.revokeDevice(id, now);
      await db.audit({ licenseId: row.license_id, event: "admin", reason: "device-revoke", platform: row.platform, hwPrefix: row.hardware_hash.slice(0, 12), now });
      return json(200, { ok: true });
    }
    if (action === "revive") {
      await db.reviveDeviceById(id, now);
      await db.audit({ licenseId: row.license_id, event: "admin", reason: "device-revive", platform: row.platform, now });
      return json(200, { ok: true });
    }
    return fail(404, "NOT_FOUND", "Unknown action.");
  }

  // GET /v1/admin/stats
  if (request.method === "GET" && parts.length === 1 && parts[0] === "stats") {
    const licenses = await db.countLicenses();
    const devices = await db.countDevices();
    const byTierStatus = await db.licenseCounts();
    const byPlatform = await db.devicesByPlatform();
    const recent = await db.recentAudit(20);
    const weekAgo = now - 7 * 86_400;
    const activations7d = await db.auditCountSince(weekAgo, "activate");
    const validates7d = await db.auditCountSince(weekAgo, "validate");
    return json(200, {
      ok: true,
      licenses,
      activeDevices: devices,
      byTierStatus,
      byPlatform,
      activations7d,
      validates7d,
      recentAudit: recent,
    });
  }

  return fail(404, "NOT_FOUND", "Unknown admin route.");
}

function publicLicense(row: LicenseRow) {
  return {
    id: row.id,
    tier: row.tier,
    status: row.status,
    customerName: row.customer_name,
    customerEmail: row.customer_email,
    note: row.note,
    source: row.source,
    keyLast4: row.key_last4,
    issuedAt: row.issued_at,
    expiresAt: row.expires_at,
    createdAt: row.created_at,
  };
}

/** The full v3 device view — every binding + descriptive fact. */
function publicDevice(d: DeviceRow) {
  return {
    id: d.id,
    platform: d.platform,
    hardwareHash: d.hardware_hash,
    hostname: d.hostname,
    osVersion: d.os_version,
    appVersion: d.app_version,
    compMachine: d.comp_machine,
    compVolume: d.comp_volume,
    compCpu: d.comp_cpu,
    cpuBrand: d.cpu_brand,
    ramMb: d.ram_mb,
    machineModel: d.machine_model,
    baseboardSerial: d.baseboard_serial,
    firmwareUuid: d.firmware_uuid,
    biosVersion: d.bios_version,
    cpuCores: d.cpu_cores,
    arch: d.arch,
    compBoard: d.comp_board,
    compFirmware: d.comp_firmware,
    factsV3: d.facts_v3 === 1,
    activatedAt: d.activated_at,
    lastSeenAt: d.last_seen_at,
    revoked: d.revoked === 1,
  };
}
