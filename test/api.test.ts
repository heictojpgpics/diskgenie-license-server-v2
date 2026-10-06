/**
 * End-to-end API tests: the REAL worker code, REAL D1 (miniflare),
 * REAL request signing — the same wire contract the desktop client
 * speaks. Covers the full activation lifecycle, device-binding rules
 * (1 Windows + 1 macOS per key), revocation, expiry, replay defense,
 * and the admin surface.
 */
import { beforeEach, describe, expect, it } from "vitest";
import { env } from "cloudflare:test";
import worker from "../src/index";
import type { Env } from "../src/types";
import { generateKey, normalizeKey } from "../src/keys";
import { publicKeyFromSeed, signToken, toHex } from "../src/crypto";
import { keyHashOf } from "../src/tokens";
import { signedRequest, hw } from "./client";
import { TEST_ADMIN_KEY, TEST_SIGNING_SEED } from "./constants";
import { INITIAL_SCHEMA } from "./schema";

const ctx = undefined as unknown as ExecutionContext;
const pubKeyHex = toHex(await publicKeyFromSeed(TEST_SIGNING_SEED));

const call = async (req: Request | Promise<Request>) => {
  const res = await worker.fetch(await req, env as unknown as Env, ctx);
  return { status: res.status, body: (await res.json()) as Record<string, any> };
};
// NOTE: `init.headers` MERGES with the bearer header — spreading the
// raw `...init` after `headers:` (the v1 helper) would replace the
// merged object and silently drop the bearer key whenever a test passed
// its own headers.
const admin = async (path: string, init?: RequestInit) => {
  const { headers, ...rest } = init ?? {};
  return call(new Request(`https://license.diskgenie.test${path}`, {
    ...rest,
    headers: { authorization: `Bearer ${TEST_ADMIN_KEY}`, ...(headers as Record<string, string> | undefined) },
  }));
};
const activate = (key: string, platform: string, hardwareHash: string) =>
  call(signedRequest("POST", "/v1/activate", {
    licenseKey: key, hardwareHash, platform,
    hostname: "DEV-PC", osVersion: "Win 11", appVersion: "0.1.0",
    compMachine: "1".repeat(64), compVolume: "2".repeat(64), compCpu: "3".repeat(64),
    cpuBrand: "Intel Core i7", ramMb: 16384, machineModel: "Dell Inc. XPS 15",
  }));
const validate = (key: string, platform: string, hardwareHash: string) =>
  call(signedRequest("POST", "/v1/validate", { licenseKey: key, hardwareHash, platform }));

beforeEach(async () => {
  for (const table of ["devices", "audit_events", "nonce_seen", "rate_buckets", "licenses"]) { // children first (FK)
      await env.DB.prepare(`DELETE FROM ${table}`).run();
    }
});
void INITIAL_SCHEMA;

describe("health + auth", () => {
  it("health is public", async () => {
    const { status, body } = await call(new Request("https://license.diskgenie.test/v1/health"));
    expect(status).toBe(200);
    expect(body.ok).toBe(true);
  });

  it("rejects unsigned requests (no HMAC)", async () => {
    const { status, body } = await call(new Request("https://license.diskgenie.test/v1/activate", {
      method: "POST",
      body: "{}",
    }));
    expect(status).toBe(403);
    expect(body.code).toBe("BAD_UA");
  });

  it("accepts the PRE-RENAME user-agent (the DiskBytes compat window)", async () => {
    // The 2026-10 product rename: every already-shipped app build sends
    // the old UA. The guard must accept BOTH until the compat window
    // retires — pinned here so a cleanup can't silently break old
    // installs. (A well-formed-but-unknown key reaching KEY_NOT_FOUND
    // PROVES the request cleared the guard: BAD_UA would 403 first.)
    const { status, body } = await call(await signedRequest(
      "POST",
      "/v1/activate",
      { licenseKey: "DB" + "1".repeat(20), hardwareHash: hw(1), platform: "windows" },
      { userAgent: "DiskBytes-License-Client/1" },
    ));
    expect(status).toBe(404);
    expect(body.code).toBe("KEY_NOT_FOUND");
  });

  it("rejects a tampered signature", async () => {
    const { status, body } = await call(await signedRequest("POST", "/v1/validate", { licenseKey: "DB" + "0".repeat(20), hardwareHash: hw(1), platform: "windows" }, { signature: "f".repeat(128) }));
    expect(status).toBe(401);
    expect(body.code).toBe("BAD_SIGNATURE");
  });

  it("rejects stale timestamps (clock skew beyond 300 s)", async () => {
    const { status, body } = await call(await signedRequest("POST", "/v1/validate", { licenseKey: "DB" + "0".repeat(20), hardwareHash: hw(1), platform: "windows" }, { timestamp: Date.now() - 400_000 }));
    expect(status).toBe(401);
    expect(body.code).toBe("BAD_TIMESTAMP");
  });

  it("rejects replayed nonces", async () => {
    const body = { licenseKey: "DB" + "0".repeat(20), hardwareHash: hw(1), platform: "windows" };
    const first = await signedRequest("POST", "/v1/validate", body);
    await call(first);
    const replay = await signedRequest("POST", "/v1/validate", body, { nonce: first.headers.get("x-db-nonce") ?? "" });
    const { status, body: rb } = await call(replay);
    expect(status).toBe(401);
    expect(rb.code).toBe("REPLAYED");
  });

  it("rejects replayed nonces on the token verification endpoint", async () => {
    const body = { token: "not-a-token" };
    const first = await signedRequest("POST", "/v1/verify", body);
    const firstResult = await call(first);
    expect(firstResult.status).toBe(200);
    expect(firstResult.body.valid).toBe(false);

    const replay = await signedRequest("POST", "/v1/verify", body, {
      nonce: first.headers.get("x-db-nonce") ?? "",
    });
    const replayResult = await call(replay);
    expect(replayResult.status).toBe(401);
    expect(replayResult.body.code).toBe("REPLAYED");
  });

  it("admin requires the bearer key", async () => {
    const { status } = await call(new Request("https://license.diskgenie.test/v1/admin/stats"));
    expect(status).toBe(401);
  });
});

describe("activation lifecycle", () => {
  it("activates a lifetime key, returns a verifiable token", async () => {
    const gen = await admin("/v1/admin/keys", {
      method: "POST",
      body: JSON.stringify({ tier: "lifetime", customerName: "Alex Morgan", customerEmail: "alex@example.com" }),
    });
    expect(gen.status).toBe(200);
    const key = gen.body.keys[0].key;
    expect(normalizeKey(key).length).toBe(22);

    const { status, body } = await activate(key, "windows", hw(7));
    expect(status).toBe(200);
    expect(body.ok).toBe(true);
    expect(body.license.tier).toBe("lifetime");
    expect(body.license.name).toBe("Alex Morgan");
    expect(body.license.expiresAt).toBeNull();

    // The token payload is the exact contract the Rust client verifies.
    const parts = String(body.token).split("."); const p = parts[0] ?? ""; const s = parts[1] ?? "";
    const payload = JSON.parse(atob(p.replace(/-/g, "+").replace(/_/g, "/")));
    expect(payload.iss).toBe("db-license");
    expect(payload.ver).toBe(1);
    // v3.1 rotation groundwork: every newly minted token names its
    // signing key (kid 1 = the current seed) and its product (aud).
    expect(payload.kid).toBe(1);
    expect(payload.aud).toBe("diskgenie");
    expect(payload.plat).toBe("windows");
    expect(payload.hw).toBe(hw(7));
    expect(payload.key).toBe(await keyHashOf(normalizeKey(key)));
    expect(payload.tier).toBe("lifetime");
    expect(payload.lexp).toBeNull();
    expect(payload.exp - payload.iat).toBe(14 * 86_400);
    // Signature verifies with the public key (the anti-spoofing core).
    const res = await call(signedRequest("POST", "/v1/verify", { token: body.token }));
    expect(res.body.valid).toBe(true);
    void s;
  });

  it("same device re-activates freely (reinstall)", async () => {
    const key = await genKey("yearly", "Renee Okafor", "renee@example.com");
    const a = await activate(key, "windows", hw(3));
    expect(a.status).toBe(200);
    const b = await activate(key, "windows", hw(3));
    expect(b.status).toBe(200);
  });

  it("one key = 1 Windows + 1 macOS — second Windows device is rejected", async () => {
    const key = await genKey("lifetime", "Sam Patel", "sam@example.com");
    const win1 = await activate(key, "windows", hw(1));
    expect(win1.status).toBe(200);
    const win2 = await activate(key, "windows", hw(2));
    expect(win2.status).toBe(409);
    expect(win2.body.code).toBe("DEVICE_SLOT_TAKEN");
    // ...but the macOS slot is still open for this key.
    const mac = await activate(key, "macos", hw(3));
    expect(mac.status).toBe(200);
    const mac2 = await activate(key, "macos", hw(4));
    expect(mac2.status).toBe(409);
  });

  it("unknown key → KEY_NOT_FOUND; malformed key → BAD_REQUEST", async () => {
    const missing = await activate("DB" + "1".repeat(20), "windows", hw(1));
    expect(missing.status).toBe(404);
    expect(missing.body.code).toBe("KEY_NOT_FOUND");
    const malformed = await call(signedRequest("POST", "/v1/activate", { licenseKey: "DB-SHORT", hardwareHash: hw(1), platform: "windows" }));
    expect(malformed.status).toBe(400);
  });

  it("validate refreshes tokens for the bound device, rejects strangers", async () => {
    const key = await genKey("yearly", "Dana Lee", "dana@example.com");
    await activate(key, "windows", hw(11));
    const ok = await validate(key, "windows", hw(11));
    expect(ok.status).toBe(200);
    expect(ok.body.ok).toBe(true);
    const stranger = await validate(key, "windows", hw(99));
    expect(stranger.status).toBe(403);
    expect(stranger.body.code).toBe("DEVICE_MISMATCH");
  });

  it("deactivate frees the slot; the same hardware can re-register", async () => {
    const key = await genKey("lifetime", "Kai Tan", "kai@example.com");
    await activate(key, "windows", hw(21));
    const off = await call(signedRequest("POST", "/v1/deactivate", { licenseKey: key, hardwareHash: hw(21), platform: "windows" }));
    expect(off.status).toBe(200);
    // The slot is free: a DIFFERENT device can now take it.
    const other = await activate(key, "windows", hw(22));
    expect(other.status).toBe(200);
    // v2: while the other device holds the slot, the ORIGINAL hardware
    // is refused (one live row per platform — the partial unique index).
    // (v1 silently created a second live row here — the race made
    // concrete; v2's storage invariant forbids it.)
    const again = await activate(key, "windows", hw(21));
    expect(again.status).toBe(409);
    expect(again.body.code).toBe("DEVICE_SLOT_TAKEN");
    // Once the OTHER device frees it, the original re-registers fine.
    await call(signedRequest("POST", "/v1/deactivate", { licenseKey: key, hardwareHash: hw(22), platform: "windows" }));
    const reReg = await activate(key, "windows", hw(21));
    expect(reReg.status).toBe(200);
  });

  it("deactivation on an unregistered device is idempotent-ok", async () => {
    const key = await genKey("lifetime", "Ivy Chan", "ivy@example.com");
    const res = await call(signedRequest("POST", "/v1/deactivate", { licenseKey: key, hardwareHash: hw(31), platform: "windows" }));
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });
});

describe("revocation and expiry (server-side enforcement)", () => {
  it("a revoked license hard-fails validation with KEY_REVOKED", async () => {
    const key = await genKey("lifetime", "Revoked Ron", "ron@example.com");
    await activate(key, "windows", hw(41));
    const list = await admin("/v1/admin/keys?limit=10");
    const id = list.body.keys.find((k: any) => k.keyLast4 === normalizeKey(key).slice(-4)).id;
    const rev = await admin(`/v1/admin/keys/${id}/revoke`, { method: "POST" });
    expect(rev.status).toBe(200);
    const val = await validate(key, "windows", hw(41));
    expect(val.status).toBe(403);
    expect(val.body.code).toBe("KEY_REVOKED");
  });

  it("an expired yearly license refuses activation with LICENSE_EXPIRED", async () => {
    const raw = normalizeKey(generateKey());
    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare(
      "INSERT INTO licenses (key_hash, key_last4, tier, status, customer_name, customer_email, issued_at, expires_at, created_at, updated_at) VALUES (?1, ?2, 'yearly', 'active', 'Expired Eve', 'eve@example.com', ?3, ?4, ?5, ?5)",
    )
      .bind(await keyHashOf(raw), raw.slice(-4), now - 400 * 86400, now - 86400, now)
      .run();
    const res = await activate(raw, "windows", hw(51));
    expect(res.status).toBe(403);
    expect(res.body.code).toBe("LICENSE_EXPIRED");
  });

  it("renew extends a yearly license and re-activates it", async () => {
    const key = await genKey("yearly", "New Nora", "nora@example.com");
    const list = await admin("/v1/admin/keys?limit=10");
    const id = list.body.keys.find((k: any) => k.keyLast4 === normalizeKey(key).slice(-4)).id;
    const renew = await admin(`/v1/admin/keys/${id}/renew`, { method: "POST", body: JSON.stringify({ days: 30 }) });
    expect(renew.status).toBe(200);
    expect(renew.body.expiresAt).toBeGreaterThan(Date.now() / 1000);
    const val = await validate(key, "windows", hw(0) === hw(0) ? hw(52) : hw(52));
    // Not yet activated on any device — DEVICE_MISMATCH is the expected
    // reason (the license itself is valid again).
    expect(val.body.code).toBe("DEVICE_MISMATCH");
  });
});

describe("admin surface", () => {
  it("generates batches and never stores raw keys", async () => {
    const gen = await admin("/v1/admin/keys", {
      method: "POST",
      body: JSON.stringify({ count: 3, tier: "yearly", customerName: "Batch Bob", customerEmail: "bob@example.com", note: "batch test" }),
    });
    expect(gen.status).toBe(200);
    expect(gen.body.keys.length).toBe(3);
    for (const k of gen.body.keys) {
      expect(normalizeKey(k.key).length).toBe(22);
      const row = await env.DB.prepare("SELECT key_hash FROM licenses WHERE key_last4 = ?1").bind(normalizeKey(k.key).slice(-4)).first<any>();
      expect(row.key_hash).toBe(await keyHashOf(normalizeKey(k.key)));
    }
  });

  it("validates generate input", async () => {
    const bad = await admin("/v1/admin/keys", {
      method: "POST",
      body: JSON.stringify({ tier: "bogus", customerName: "x", customerEmail: "x@y.z" }),
    });
    expect(bad.status).toBe(400);
    const badEmail = await admin("/v1/admin/keys", {
      method: "POST",
      body: JSON.stringify({ tier: "lifetime", customerName: "x", customerEmail: "not-an-email" }),
    });
    expect(badEmail.status).toBe(400);
  });

  it("lists licenses without raw keys, reports stats", async () => {
    await genKey("lifetime", "Stat Sue", "sue@example.com");
    const list = await admin("/v1/admin/keys?limit=5");
    expect(list.status).toBe(200);
    expect(list.body.keys[0]).not.toHaveProperty("key");
    expect(list.body.keys[0]).toHaveProperty("keyLast4");
    const stats = await admin("/v1/admin/stats");
    expect(stats.status).toBe(200);
    expect(stats.body.licenses).toBeGreaterThanOrEqual(1);
  });

  it("device reset (support) frees the slot", async () => {
    const key = await genKey("lifetime", "Reset Rae", "rae@example.com");
    await activate(key, "windows", hw(61));
    const list = await admin("/v1/admin/keys?limit=10");
    const lic = list.body.keys.find((k: any) => k.keyLast4 === normalizeKey(key).slice(-4));
    const detail = await admin(`/v1/admin/keys/${lic.id}`);
    const device = detail.body.devices[0];
    const reset = await admin(`/v1/admin/devices/${device.id}/revoke`, { method: "POST" });
    expect(reset.status).toBe(200);
    // The slot is free now — a different device can activate.
    const other = await activate(key, "windows", hw(62));
    expect(other.status).toBe(200);
  });
});

describe("transactional + idempotent batch generation", () => {
  const countAll = async () =>
    (await env.DB.prepare("SELECT COUNT(*) AS n FROM licenses").first<{ n: number }>())?.n ?? 0;

  it("generation commits the exact requested count (all-or-nothing positive path)", async () => {
    const gen = await admin("/v1/admin/keys", {
      method: "POST",
      body: JSON.stringify({ count: 7, tier: "lifetime", customerName: "Count Check", customerEmail: "count@example.com" }),
    });
    expect(gen.status).toBe(200);
    expect(gen.body.keys.length).toBe(7);
    expect(await countAll()).toBe(7); // nothing more, nothing less
  });

  it("a mid-batch DB failure commits ZERO rows (one D1 batch = one transaction)", async () => {
    // Pre-existing row whose key_hash the injected statement collides
    // with — guarantees a mid-batch UNIQUE violation regardless of the
    // random keys the route mints.
    const now = Math.floor(Date.now() / 1000);
    const collisionHash = "e" + "0".repeat(63);
    await env.DB.prepare(
      "INSERT INTO licenses (key_hash, key_last4, tier, status, customer_name, customer_email, issued_at, created_at, updated_at) VALUES (?1, 'BEEF', 'lifetime', 'active', 'Collision', 'col@example.com', ?2, ?2, ?2)",
    ).bind(collisionHash, now).run();
    expect(await countAll()).toBe(1);

    // Wrap env.DB.batch (the primitive the route must use for ONE
    // transactional insert) so the route's batch is spliced with a
    // colliding statement right after its FIRST insert. If the route
    // still inserted key-by-key, insert #1 would already be committed;
    // all-or-nothing means the count stays exactly at 1.
    const dbAny = env.DB as { batch: (stmts: D1PreparedStatement[]) => Promise<unknown[]> };
    const realBatch = dbAny.batch.bind(env.DB);
    dbAny.batch = async (stmts: D1PreparedStatement[]) => {
      const collide = env.DB.prepare(
        "INSERT INTO licenses (key_hash, key_last4, tier, status, customer_name, customer_email, issued_at, created_at, updated_at) VALUES (?1, 'BEEF', 'yearly', 'active', 'Collision2', 'col2@example.com', ?2, ?2, ?2)",
      ).bind(collisionHash, now);
      return realBatch([stmts[0]!, collide, ...stmts.slice(1)]);
    };
    try {
      const gen = await admin("/v1/admin/keys", {
        method: "POST",
        body: JSON.stringify({ count: 3, tier: "yearly", customerName: "Roll Back", customerEmail: "rb@example.com" }),
      });
      expect(gen.status).toBe(500);
      expect(gen.body.code).toBe("GEN_FAILED");
    } finally {
      dbAny.batch = realBatch;
    }
    // The failed batch (and every retry) committed nothing.
    expect(await countAll()).toBe(1);
  });

  it("the same Idempotency-Key replays the committed batch without duplicates", async () => {
    const body = JSON.stringify({ count: 3, tier: "lifetime", customerName: "Idem Ian", customerEmail: "ian@example.com" });
    const first = await admin("/v1/admin/keys", { method: "POST", headers: { "Idempotency-Key": "webhook-retry-1" }, body });
    expect(first.status).toBe(200);
    expect(first.body.keys.length).toBe(3);
    expect(first.body.replayed).toBeUndefined(); // first hit returns RAW keys
    const rawKeys = (first.body.keys as { key: string }[]).map((k) => k.key);
    for (const k of rawKeys) expect(normalizeKey(k).length).toBe(22);

    // The webhook retries the SAME request (network blip, at-least-once
    // delivery) with the same Idempotency-Key.
    const second = await admin("/v1/admin/keys", { method: "POST", headers: { "Idempotency-Key": "webhook-retry-1" }, body });
    expect(second.status).toBe(200);
    expect(second.body.replayed).toBe(true);
    expect(second.body.keys.length).toBe(3);
    // Replays carry the publicLicense view ONLY — raw keys exist only in
    // the FIRST response (they are never stored, so cannot be re-shown).
    for (const k of second.body.keys as Record<string, any>[]) {
      expect(k.key).toBeUndefined();
      expect(k.keyLast4).toBeDefined();
    }
    // No duplicates were created, and the replayed rows ARE the first batch.
    expect(await countAll()).toBe(3);
    const list = await admin("/v1/admin/keys?limit=10");
    expect(list.body.total).toBe(3);
    const last4s = (list.body.keys as { keyLast4: string }[]).map((k) => k.keyLast4).sort();
    expect(last4s).toEqual(rawKeys.map((k) => normalizeKey(k).slice(-4)).sort());

    // A DIFFERENT idempotency key mints a fresh batch (not a replay).
    const third = await admin("/v1/admin/keys", { method: "POST", headers: { "Idempotency-Key": "webhook-retry-2" }, body });
    expect(third.status).toBe(200);
    expect(third.body.replayed).toBeUndefined();
    expect(await countAll()).toBe(6);
  });

  it("idempotencyKey also works as a JSON body field", async () => {
    const body = JSON.stringify({ count: 1, tier: "yearly", customerName: "Body Field", customerEmail: "bf@example.com", idempotencyKey: "body-field-1" });
    const a = await admin("/v1/admin/keys", { method: "POST", body });
    expect(a.status).toBe(200);
    const b = await admin("/v1/admin/keys", { method: "POST", body });
    expect(b.status).toBe(200);
    expect(b.body.replayed).toBe(true);
    expect(await countAll()).toBe(1);
  });
});

describe("token kid + aud claims (rotation groundwork)", () => {
  // A manually minted token in the current wire shape — `claims`
  // overrides the rotation claims so each test constructs exactly the
  // variant it needs (legacy, wrong-aud, unknown-kid, ...).
  const mintManual = async (claims: { kid?: number; aud?: string }): Promise<string> => {
    const now = Math.floor(Date.now() / 1000);
    return signToken(TEST_SIGNING_SEED, {
      iss: "db-license", ver: 1, jti: "ab".repeat(16), iat: now, exp: now + 86_400,
      key: "cd".repeat(32), tier: "lifetime", name: "Manual Mint", email: "mm@example.com",
      hw: "ef".repeat(32), plat: "windows", lexp: null, ...claims,
    });
  };
  const verifyViaApi = (token: string) => call(signedRequest("POST", "/v1/verify", { token }));

  it("a LEGACY token (minted before kid/aud) still verifies — the compat window", async () => {
    // The deployed fleet carries tokens without the new claims; the
    // verification path must accept them unchanged until the fleet has
    // turned over (same principle as the UA compat window).
    const res = await verifyViaApi(await mintManual({}));
    expect(res.status).toBe(200);
    expect(res.body.valid).toBe(true);
    expect(res.body.payload.kid).toBeUndefined();
    expect(res.body.payload.aud).toBeUndefined();
  });

  it("a token minted for ANOTHER product fails with 403 BAD_AUDIENCE", async () => {
    const res = await verifyViaApi(await mintManual({ aud: "other-product" }));
    expect(res.status).toBe(403);
    expect(res.body.ok).toBe(false);
    expect(res.body.code).toBe("BAD_AUDIENCE");
  });

  it("a token naming an UNKNOWN key id fails verification (BAD_SIGNATURE)", async () => {
    // Signature is genuine, but the token claims a key we never minted
    // with — a rotation-claim forgery, rejected at the signature level.
    const res = await verifyViaApi(await mintManual({ kid: 7 }));
    expect(res.status).toBe(401);
    expect(res.body.code).toBe("BAD_SIGNATURE");
  });

  it("a manually minted kid=1/aud=diskgenie token verifies", async () => {
    const res = await verifyViaApi(await mintManual({ kid: 1, aud: "diskgenie" }));
    expect(res.status).toBe(200);
    expect(res.body.valid).toBe(true);
    expect(res.body.payload.kid).toBe(1);
    expect(res.body.payload.aud).toBe("diskgenie");
  });
});

/** Generate one key via the admin API and return the raw key. */
async function genKey(tier: "yearly" | "lifetime", name: string, email: string): Promise<string> {
  const res = await admin("/v1/admin/keys", {
    method: "POST",
    body: JSON.stringify({ tier, customerName: name, customerEmail: email }),
  });
  if (res.status !== 200) throw new Error(`genKey failed: ${res.status}`);
  return res.body.keys[0].key as string;
}
