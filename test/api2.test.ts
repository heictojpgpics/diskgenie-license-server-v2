/**
 * v2 regression + hardening suite: the device-facts lifecycle (THE
 * owner-reported wipe bug), race-safe slot binding, rate limits,
 * change detection, and the expanded admin surface. Runs against the
 * REAL worker + REAL D1 exactly like api.test.ts.
 */
import { beforeEach, describe, expect, it } from "vitest";
import { env } from "cloudflare:test";
import worker from "../src/index";
import type { Env } from "../src/types";
import { keyHashOf } from "../src/tokens";
import { hmacHex, ipHashOf, randomHex, sha256Hex } from "../src/crypto";
import { signedRequest, hw, UA } from "./client";
import { TEST_ADMIN_KEY, TEST_CLIENT_SECRET } from "./constants";

const ctx = undefined as unknown as ExecutionContext;

const call = async (req: Request | Promise<Request>) => {
  const res = await worker.fetch(await req, env as unknown as Env, ctx);
  return { status: res.status, body: (await res.json()) as Record<string, any> };
};
const admin = async (path: string, init?: RequestInit) =>
  call(new Request(`https://license.diskgenie.test${path}`, {
    headers: { authorization: `Bearer ${TEST_ADMIN_KEY}`, ...init?.headers },
    ...init,
  }));

beforeEach(async () => {
  for (const table of ["devices", "audit_events", "nonce_seen", "rate_buckets", "licenses"]) {
    await env.DB.prepare(`DELETE FROM ${table}`).run();
  }
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

/** The license row id for a raw key (admin lookup). */
async function licenseIdOf(key: string): Promise<number> {
  const res = await admin("/v1/admin/lookup", {
    method: "POST",
    body: JSON.stringify({ key }),
  });
  if (res.status !== 200) throw new Error(`lookup failed: ${res.status}`);
  return res.body.license.id as number;
}

const FULL_FACTS = {
  hostname: "REPRO-PC",
  osVersion: "Windows 11.0.26100",
  appVersion: "0.1.0",
  compMachine: "a".repeat(64),
  compVolume: "b".repeat(64),
  compCpu: "c".repeat(64),
  cpuBrand: "Intel Core i7-1260P",
  ramMb: 16384,
  machineModel: "Dell Inc. XPS 15 9520",
  // v3 facts
  baseboardSerial: "BX24RTK81",
  firmwareUuid: "4C4C4544-0042-4E10-8032-B2C04F475030",
  biosVersion: "DELL A08",
  cpuCores: 16,
  arch: "x86_64",
  compBoard: "d".repeat(64),
  compFirmware: "e".repeat(64),
};

describe("the device-facts lifecycle (v2 core fix)", () => {
  it("stores the full v2 claim at activation (admin sees every fact)", async () => {
    const key = await genKey("lifetime", "Alex Morgan", "alex@example.com");
    const act = await call(signedRequest("POST", "/v1/activate", {
      licenseKey: key, hardwareHash: hw(7), platform: "windows", ...FULL_FACTS,
    }));
    expect(act.status).toBe(200);
    const detail = await admin(`/v1/admin/keys/${await licenseIdOf(key)}`);
    const d = detail.body.devices[0]!;
    expect(d.hostname).toBe("REPRO-PC");
    expect(d.osVersion).toBe("Windows 11.0.26100");
    expect(d.appVersion).toBe("0.1.0");
    expect(d.compMachine).toBe("a".repeat(64));
    expect(d.compVolume).toBe("b".repeat(64));
    expect(d.compCpu).toBe("c".repeat(64));
    expect(d.cpuBrand).toBe("Intel Core i7-1260P");
    expect(d.ramMb).toBe(16384);
    expect(d.machineModel).toBe("Dell Inc. XPS 15 9520");
  });

  it("REGRESSION: validate with the full claim KEEPS the facts (v1 wiped them)", async () => {
    const key = await genKey("lifetime", "Alex Morgan", "alex@example.com");
    await call(signedRequest("POST", "/v1/activate", {
      licenseKey: key, hardwareHash: hw(7), platform: "windows", ...FULL_FACTS,
    }));
    // The v2 app sends the FULL claim on validate — the v1 app sent
    // only {licenseKey, hardwareHash, platform} and v1's server then
    // SET hostname/os_version/app_version to NULL. This is the exact
    // owner-reported "doesn't save hostname / windows version" repro.
    const val = await call(signedRequest("POST", "/v1/validate", {
      licenseKey: key, hardwareHash: hw(7), platform: "windows",
      ...FULL_FACTS, osVersion: "Windows 12.0.27000", appVersion: "0.2.0",
    }));
    expect(val.status).toBe(200);
    const detail = await admin(`/v1/admin/keys/${await licenseIdOf(key)}`);
    const d = detail.body.devices[0]!;
    expect(d.hostname).toBe("REPRO-PC");
    expect(d.osVersion).toBe("Windows 12.0.27000");
    expect(d.appVersion).toBe("0.2.0");
    expect(d.cpuBrand).toBe(FULL_FACTS.cpuBrand);
    expect(d.ramMb).toBe(16384);
  });

  it("validate with a SPARSE claim (v1 client shape) never regresses stored facts", async () => {
    const key = await genKey("lifetime", "Alex Morgan", "alex@example.com");
    await call(signedRequest("POST", "/v1/activate", {
      licenseKey: key, hardwareHash: hw(7), platform: "windows", ...FULL_FACTS,
    }));
    // A v1 client (or a collection hiccup) sends no facts at all.
    const val = await call(signedRequest("POST", "/v1/validate", {
      licenseKey: key, hardwareHash: hw(7), platform: "windows",
    }));
    expect(val.status).toBe(200);
    const detail = await admin(`/v1/admin/keys/${await licenseIdOf(key)}`);
    const d = detail.body.devices[0]!;
    expect(d.hostname).toBe("REPRO-PC");
    expect(d.osVersion).toBe("Windows 11.0.26100");
    expect(d.appVersion).toBe("0.1.0");
    expect(d.machineModel).toBe("Dell Inc. XPS 15 9520");
  });

  it("re-activation with a sparse claim also keeps the last known good facts", async () => {
    const key = await genKey("lifetime", "Alex Morgan", "alex@example.com");
    await call(signedRequest("POST", "/v1/activate", {
      licenseKey: key, hardwareHash: hw(7), platform: "windows", ...FULL_FACTS,
    }));
    const re = await call(signedRequest("POST", "/v1/activate", {
      licenseKey: key, hardwareHash: hw(7), platform: "windows",
      hostname: "REPRO-PC",
    }));
    expect(re.status).toBe(200);
    const detail = await admin(`/v1/admin/keys/${await licenseIdOf(key)}`);
    const d = detail.body.devices[0]!;
    expect(d.osVersion).toBe("Windows 11.0.26100");
    expect(d.cpuBrand).toBe(FULL_FACTS.cpuBrand);
  });

  it("change detection: an OS/app change lands in the audit trail with a diff", async () => {
    const key = await genKey("lifetime", "Alex Morgan", "alex@example.com");
    await call(signedRequest("POST", "/v1/activate", {
      licenseKey: key, hardwareHash: hw(7), platform: "windows", ...FULL_FACTS,
    }));
    await call(signedRequest("POST", "/v1/validate", {
      licenseKey: key, hardwareHash: hw(7), platform: "windows",
      ...FULL_FACTS, osVersion: "Windows 12.0.27000",
    }));
    const events = await env.DB.prepare(
      "SELECT event, detail FROM audit_events WHERE event = 'device_update'",
    ).all<{ event: string; detail: string }>();
    expect(events.results.length).toBe(1);
    const diff = JSON.parse(events.results[0]!.detail);
    expect(diff.osVersion).toEqual(["Windows 11.0.26100", "Windows 12.0.27000"]);
  });

  it("garbage/oversized claim fields are dropped, not stored", async () => {
    const key = await genKey("lifetime", "Alex Morgan", "alex@example.com");
    const act = await call(signedRequest("POST", "/v1/activate", {
      licenseKey: key, hardwareHash: hw(7), platform: "windows",
      ...FULL_FACTS,
      hostname: "NUL\x00INJ",                    // control char → CLEANED (v3), not dropped
      cpuBrand: "x".repeat(400),                  // oversized → truncated to 120
      compMachine: "not-hex!",                    // invalid → dropped
      ramMb: 9_999_999,                           // out of range → clamped (1 TB max)
    }));
    expect(act.status).toBe(200);
    const detail = await admin(`/v1/admin/keys/${await licenseIdOf(key)}`);
    const d = detail.body.devices[0]!;
    // v3: control chars are scrubbed ("NUL\x00INJ" → "NUL INJ") — the
    // v2 drop-to-NULL was the "cpu brand doesn't work" root cause.
    expect(d.hostname).toBe("NUL INJ");
    expect(d.cpuBrand.length).toBe(120);
    expect(d.compMachine).toBeNull();
    expect(d.ramMb).toBe(1_048_576);
  });

  it("v3 facts round-trip: baseboard/firmware/bios/cores/arch stored", async () => {
    const key = await genKey("lifetime", "V Three", "v3@example.com");
    const act = await call(signedRequest("POST", "/v1/activate", {
      licenseKey: key, hardwareHash: hw(9), platform: "windows", ...FULL_FACTS,
    }));
    expect(act.status).toBe(200);
    const detail = await admin(`/v1/admin/keys/${await licenseIdOf(key)}`);
    const d = detail.body.devices[0]!;
    expect(d.baseboardSerial).toBe("BX24RTK81");
    expect(d.firmwareUuid).toBe("4c4c4544-0042-4e10-8032-b2c04f475030");
    expect(d.biosVersion).toBe("DELL A08");
    expect(d.cpuCores).toBe(16);
    expect(d.arch).toBe("x86_64");
    expect(d.compBoard).toBe("d".repeat(64));
    expect(d.compFirmware).toBe("e".repeat(64));
    expect(d.factsV3).toBe(true);
  });

  it("v3 sanitizer: cpuCores clamps, arch whitelist, garbage uuid dropped", async () => {
    const key = await genKey("lifetime", "Edge Case", "edge@example.com");
    const act = await call(signedRequest("POST", "/v1/activate", {
      licenseKey: key, hardwareHash: hw(10), platform: "windows",
      cpuCores: 9999,                 // out of range → clamped (1024 max)
      arch: "powerpc",                // not whitelisted → dropped
      firmwareUuid: "not-a-uuid",     // malformed → dropped
      cpuBrand: "  QEMU  \x00\x00 Virtual  CPU\x00 ",  // NUL-padded brand → cleaned
    }));
    expect(act.status).toBe(200);
    const detail = await admin(`/v1/admin/keys/${await licenseIdOf(key)}`);
    const d = detail.body.devices[0]!;
    expect(d.cpuCores).toBe(1024);
    expect(d.arch).toBeNull();
    expect(d.firmwareUuid).toBeNull();
    expect(d.cpuBrand).toBe("QEMU Virtual CPU");
  });

  it("v3 wipe regression: sparse revalidation keeps the v3 facts (COALESCE)", async () => {
    const key = await genKey("lifetime", "Sparse V3", "sparse@example.com");
    await call(signedRequest("POST", "/v1/activate", {
      licenseKey: key, hardwareHash: hw(11), platform: "windows", ...FULL_FACTS,
    }));
    await call(signedRequest("POST", "/v1/validate", {
      // v2-era client: ONLY the v2 fields, no v3 facts at all
      licenseKey: key, hardwareHash: hw(11), platform: "windows",
      hostname: "REPRO-PC",
    }));
    const detail = await admin(`/v1/admin/keys/${await licenseIdOf(key)}`);
    const d = detail.body.devices[0]!;
    expect(d.baseboardSerial).toBe("BX24RTK81");
    expect(d.firmwareUuid).toBe("4c4c4544-0042-4e10-8032-b2c04f475030");
    expect(d.cpuCores).toBe(16);
    expect(d.arch).toBe("x86_64");
    expect(d.compBoard).toBe("d".repeat(64));
    expect(d.compFirmware).toBe("e".repeat(64));
  });

  it("v3 change detection: a core-count / board change lands in the diff", async () => {
    const key = await genKey("lifetime", "Diff V3", "diffv3@example.com");
    await call(signedRequest("POST", "/v1/activate", {
      licenseKey: key, hardwareHash: hw(12), platform: "windows", ...FULL_FACTS,
    }));
    await call(signedRequest("POST", "/v1/validate", {
      licenseKey: key, hardwareHash: hw(12), platform: "windows",
      ...FULL_FACTS, cpuCores: 8, baseboardSerial: "BX999REPLACED", compBoard: "f".repeat(64),
    }));
    const events = await env.DB.prepare(
      "SELECT detail FROM audit_events WHERE event = 'device_update'",
    ).all<{ detail: string }>();
    expect(events.results.length).toBe(1);
    const diff = JSON.parse(events.results[0]!.detail);
    expect(diff.cpuCores).toEqual(["16", "8"]);
    expect(diff.baseboardSerial).toEqual(["BX24RTK81", "BX999REPLACED"]);
    expect(diff.compBoard).toEqual(["d".repeat(64), "f".repeat(64)]);
  });
});

describe("race-safe slot binding (the storage invariant)", () => {
  it("the partial unique index blocks a second live row even by direct SQL", async () => {
    const key = await genKey("lifetime", "Race Test", "race@example.com");
    const hash = await keyHashOf(key);
    const now = Math.floor(Date.now() / 1000);
    const ins = await env.DB.prepare(
      "INSERT INTO devices (license_id, platform, hardware_hash, activated_at, last_seen_at, revoked) VALUES ((SELECT id FROM licenses WHERE key_hash = ?1), 'windows', ?2, ?3, ?3, 0)",
    ).bind(hash, hw(1), now).run();
    expect(ins.success).toBe(true);
    // A second LIVE windows row for the same license must violate the index.
    await expect(
      env.DB.prepare(
        "INSERT INTO devices (license_id, platform, hardware_hash, activated_at, last_seen_at, revoked) VALUES ((SELECT id FROM licenses WHERE key_hash = ?1), 'windows', ?2, ?3, ?3, 0)",
      ).bind(hash, hw(2), now).run(),
    ).rejects.toThrow(/UNIQUE constraint failed/);
    // A revoked row is fine (the index is partial).
    const rev = await env.DB.prepare(
      "INSERT INTO devices (license_id, platform, hardware_hash, activated_at, last_seen_at, revoked) VALUES ((SELECT id FROM licenses WHERE key_hash = ?1), 'windows', ?2, ?3, ?3, 1)",
    ).bind(hash, hw(3), now).run();
    expect(rev.success).toBe(true);
    // And the macOS slot is independent.
    const mac = await env.DB.prepare(
      "INSERT INTO devices (license_id, platform, hardware_hash, activated_at, last_seen_at, revoked) VALUES ((SELECT id FROM licenses WHERE key_hash = ?1), 'macos', ?2, ?3, ?3, 0)",
    ).bind(hash, hw(4), now).run();
    expect(mac.success).toBe(true);
  });

  it("a revived row cannot displace the device that took its slot", async () => {
    const key = await genKey("lifetime", "Revive Test", "revive@example.com");
    const id = await licenseIdOf(key);
    // hw(1) registers, then support resets it, then hw(2) takes the slot.
    await call(signedRequest("POST", "/v1/activate", { licenseKey: key, hardwareHash: hw(1), platform: "windows", ...FULL_FACTS }));
    const detail1 = await admin(`/v1/admin/keys/${id}`);
    const dev1 = detail1.body.devices[0];
    await admin(`/v1/admin/devices/${dev1.id}/revoke`, { method: "POST" });
    await call(signedRequest("POST", "/v1/activate", { licenseKey: key, hardwareHash: hw(2), platform: "windows", ...FULL_FACTS }));
    // hw(1) tries to come back while hw(2) is live → refused.
    const back = await call(signedRequest("POST", "/v1/activate", { licenseKey: key, hardwareHash: hw(1), platform: "windows", ...FULL_FACTS }));
    expect(back.status).toBe(409);
    expect(back.body.code).toBe("DEVICE_SLOT_TAKEN");
    // Once support resets hw(2)'s row, hw(1) revives.
    const detail2 = await admin(`/v1/admin/keys/${id}`);
    const dev2 = detail2.body.devices.find((d: any) => d.hardwareHash === hw(2))!;
    await admin(`/v1/admin/devices/${dev2.id}/revoke`, { method: "POST" });
    const again = await call(signedRequest("POST", "/v1/activate", { licenseKey: key, hardwareHash: hw(1), platform: "windows", ...FULL_FACTS }));
    expect(again.status).toBe(200);
  });
});

describe("rate limiting (429 contract is real now)", () => {
  it("the 11th activate attempt on one key within the window is 429", async () => {
    const key = await genKey("lifetime", "Rate Test", "rate@example.com");
    // 10 allowed (default keyLimit), the 11th refused. Attempts that
    // fail structure (KEY_NOT_FOUND etc.) still consume the bucket —
    // brute-force noise is exactly what the limit is for.
    let last = 0;
    for (let i = 0; i < 11; i++) {
      last = (await call(signedRequest("POST", "/v1/activate", {
        licenseKey: key, hardwareHash: hw(10 + i), platform: "windows", ...FULL_FACTS,
      }))).status;
    }
    expect(last).toBe(429);
    // A DIFFERENT key is unaffected (per-key buckets).
    const other = await genKey("lifetime", "Rate Other", "other@example.com");
    const ok = await call(signedRequest("POST", "/v1/activate", {
      licenseKey: other, hardwareHash: hw(1), platform: "windows", ...FULL_FACTS,
    }));
    expect(ok.status).toBe(200);
  });

  it("a new hour window resets the bucket", async () => {
    const key = await genKey("lifetime", "Reset Test", "reset@example.com");
    for (let i = 0; i < 10; i++) {
      await call(signedRequest("POST", "/v1/activate", {
        licenseKey: key, hardwareHash: hw(20 + i), platform: "windows", ...FULL_FACTS,
      }));
    }
    // Time-travel the bucket to the previous window (the worker reads
    // Date.now() — we simulate the window boundary directly in D1).
    const stale = Math.floor(Date.now() / 1000) - 7_200;
    await env.DB.prepare("UPDATE rate_buckets SET window_start = ?1").bind(stale).run();
    // Same hardware as the registered device (hw(20)) → a refresh,
    // so the only thing that could refuse it is the rate limit.
    const fresh = await call(signedRequest("POST", "/v1/activate", {
      licenseKey: key, hardwareHash: hw(20), platform: "windows", ...FULL_FACTS,
    }));
    expect(fresh.status).toBe(200);
  });
});

describe("admin v2 surface", () => {
  it("lookup resolves a RAW key to license + devices", async () => {
    const key = await genKey("lifetime", "Look Up", "lookup@example.com");
    await call(signedRequest("POST", "/v1/activate", { licenseKey: key, hardwareHash: hw(7), platform: "windows", ...FULL_FACTS }));
    const res = await admin("/v1/admin/lookup", {
      method: "POST",
      body: JSON.stringify({ key }),
    });
    expect(res.status).toBe(200);
    expect(res.body.license.customerEmail).toBe("lookup@example.com");
    expect(res.body.license.keyLast4).toBe(key.slice(-4));
    expect(res.body.devices.length).toBe(1);
    expect(res.body.devices[0].hostname).toBe("REPRO-PC");
    // No raw key material leaks back.
    expect(JSON.stringify(res.body.license)).not.toContain(key);
  });

  it("keys list filters by customer email", async () => {
    await genKey("lifetime", "Filter A", "filter@example.com");
    await genKey("yearly", "Filter B", "filter@example.com");
    await genKey("lifetime", "Other C", "other@example.com");
    const res = await admin("/v1/admin/keys?email=filter@example.com");
    expect(res.status).toBe(200);
    expect(res.body.total).toBe(2);
    expect(res.body.keys.every((k: any) => k.customerEmail === "filter@example.com")).toBe(true);
  });

  it("transfer updates identity and the next token carries it", async () => {
    const key = await genKey("lifetime", "Old Name", "old@example.com");
    const id = await licenseIdOf(key);
    const res = await admin(`/v1/admin/keys/${id}/transfer`, {
      method: "POST",
      body: JSON.stringify({ name: "New Name", email: "new@example.com" }),
    });
    expect(res.status).toBe(200);
    expect(res.body.license.customerEmail).toBe("new@example.com");
    const val = await call(signedRequest("POST", "/v1/activate", {
      licenseKey: key, hardwareHash: hw(7), platform: "windows", ...FULL_FACTS,
    }));
    const payload = JSON.parse(atob(String(val.body.token).split(".")[0]!.replace(/-/g, "+").replace(/_/g, "/")));
    expect(payload.name).toBe("New Name");
    expect(payload.email).toBe("new@example.com");
  });

  it("refund marks a license refunded and blocks activation", async () => {
    const key = await genKey("lifetime", "Refund Test", "refund@example.com");
    const id = await licenseIdOf(key);
    const res = await admin(`/v1/admin/keys/${id}/refund`, { method: "POST" });
    expect(res.status).toBe(200);
    const act = await call(signedRequest("POST", "/v1/activate", {
      licenseKey: key, hardwareHash: hw(7), platform: "windows", ...FULL_FACTS,
    }));
    expect(act.status).toBe(403);
    expect(act.body.code).toBe("KEY_REFUNDED");
  });

  it("the global device census joins license identity", async () => {
    const key = await genKey("lifetime", "Census Test", "census@example.com");
    await call(signedRequest("POST", "/v1/activate", { licenseKey: key, hardwareHash: hw(7), platform: "windows", ...FULL_FACTS }));
    const res = await admin("/v1/admin/devices?limit=10");
    expect(res.status).toBe(200);
    const mine = res.body.devices.find((d: any) => d.hardwareHash === hw(7))!;
    expect(mine).toBeDefined();
    expect(mine.customerEmail).toBe("census@example.com");
    expect(mine.hostname).toBe("REPRO-PC");
    expect(mine.machineModel).toBe("Dell Inc. XPS 15 9520");
  });

  it("stats reports per-tier/status, per-platform, and 7-day volume", async () => {
    const key = await genKey("yearly", "Stats One", "stats1@example.com");
    await genKey("lifetime", "Stats Two", "stats2@example.com");
    await call(signedRequest("POST", "/v1/activate", { licenseKey: key, hardwareHash: hw(7), platform: "windows", ...FULL_FACTS }));
    const res = await admin("/v1/admin/stats");
    expect(res.status).toBe(200);
    expect(res.body.licenses).toBe(2);
    expect(res.body.byTierStatus.length).toBe(2);
    expect(res.body.byPlatform.find((p: any) => p.platform === "windows").n).toBe(1);
    expect(res.body.activations7d).toBe(1);
    expect(res.body.validates7d).toBe(0);
  });

  it("generate stores the source tag (webhook vs admin)", async () => {
    const res = await admin("/v1/admin/keys", {
      method: "POST",
      body: JSON.stringify({ tier: "lifetime", customerName: "Hook Bot", customerEmail: "hook@example.com", source: "webhook" }),
    });
    expect(res.status).toBe(200);
    const id = await licenseIdOf(res.body.keys[0].key);
    const detail = await admin(`/v1/admin/keys/${id}`);
    expect(detail.body.license.source).toBe("webhook");
  });
});

describe("admin rate limiting (brute-force containment)", () => {
  // The bucket window the code computes (fixed hour window) — pre-seeding
  // a bucket at a chosen count lets each test sit exactly at the edge
  // instead of burning 120 real requests.
  const windowStart = () => Math.floor(Date.now() / 1000 / 3_600) * 3_600;
  const seedBucket = async (key: string, count: number) => {
    await env.DB.prepare("INSERT INTO rate_buckets (bucket_key, window_start, count) VALUES (?1, ?2, ?3)")
      .bind(key, windowStart(), count)
      .run();
  };

  it("hammering an admin route past the per-route limit returns 429", async () => {
    // 115 already consumed → five more pass (120), the sixth crosses.
    await seedBucket("rl:admin:GET stats", 115);
    let last = 0;
    for (let i = 0; i < 6; i++) {
      last = (await admin("/v1/admin/stats")).status;
    }
    expect(last).toBe(429);
    // The refused request carries the same error body shape as the app routes.
    const res = await admin("/v1/admin/stats");
    expect(res.status).toBe(429);
    expect(res.body.ok).toBe(false);
    expect(res.body.code).toBe("RATE_LIMITED");
  });

  it("the limit fires BEFORE the bearer check — invalid keys burn the bucket", async () => {
    await seedBucket("rl:admin:POST keys", 120);
    // A WRONG bearer key would normally 401; the exhausted bucket 429s
    // first — that is the point: brute force cannot probe ADMIN_API_KEY
    // without limit.
    const bad = await call(new Request("https://license.diskgenie.test/v1/admin/keys", {
      method: "POST",
      headers: { authorization: "Bearer wrong-key", "content-type": "application/json" },
      body: JSON.stringify({ tier: "lifetime", customerName: "x", customerEmail: "x@y.z" }),
    }));
    expect(bad.status).toBe(429);
    expect(bad.body.code).toBe("RATE_LIMITED");
    // ...and a VALID key is refused in the same window too.
    const good = await admin("/v1/admin/keys", {
      method: "POST",
      body: JSON.stringify({ tier: "lifetime", customerName: "y", customerEmail: "y@z.w" }),
    });
    expect(good.status).toBe(429);
  });

  it("the per-IP admin bucket limits each source across ALL admin routes", async () => {
    // No cf-connecting-ip in the test harness → the worker hashes the
    // "unknown" IP; compute the same salted hash to pre-exhaust the bucket.
    const ipHash = await ipHashOf(env as unknown as Env, null);
    await seedBucket(`rl:admin:ip:${ipHash}`, 240);
    // A DIFFERENT route (fresh per-route bucket) is still refused: the
    // per-IP bucket spans every admin route.
    const res = await admin("/v1/admin/stats");
    expect(res.status).toBe(429);
    expect(res.body.code).toBe("RATE_LIMITED");
  });
});

describe("protocol hardening", () => {
  it("oversized bodies are rejected before parsing", async () => {
    const big = { licenseKey: "DB" + "0".repeat(20), hardwareHash: hw(1), platform: "windows", pad: "x".repeat(20_000) };
    const res = await call(signedRequest("POST", "/v1/activate", big));
    expect(res.status).toBe(400);
    expect(res.body.code).toBe("BAD_REQUEST");
  });

  it("oversized bodies on /v1/verify are rejected too (the same guard)", async () => {
    // The debug endpoint must share the app routes' body-size guard —
    // it is HMAC-authenticated like them, so it is the same abuse
    // surface (the guard order is size-first, even before the HMAC).
    const res = await call(signedRequest("POST", "/v1/verify", { token: "x".repeat(20_000) }));
    expect(res.status).toBe(400);
    expect(res.body.code).toBe("BAD_REQUEST");
  });

  it("an invalid JSON body on /v1/verify is a 400, not a 500", async () => {
    // Signed raw garbage: the request clears the HMAC guard (it is a
    // valid signature over invalid-JSON bytes — a client bug), and must
    // be reported as the client's fault, not SERVER_ERROR.
    const raw = "not-json{";
    const timestamp = Date.now();
    const nonce = randomHex(16);
    const bodyHash = await sha256Hex(raw);
    const signature = await hmacHex(TEST_CLIENT_SECRET, `${timestamp}.${nonce}.POST./v1/verify.${bodyHash}`);
    const res = await call(new Request("https://license.diskgenie.test/v1/verify", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "user-agent": UA,
        "x-db-app": "diskgenie",
        "x-db-version": "0.1.0",
        "x-db-timestamp": String(timestamp),
        "x-db-nonce": nonce,
        "x-db-signature": signature,
      },
      body: raw,
    }));
    expect(res.status).toBe(400);
    expect(res.body.code).toBe("BAD_REQUEST");
  });

  it("deactivate rejects a garbage platform instead of coercing to windows", async () => {
    const key = await genKey("lifetime", "Plat Test", "plat@example.com");
    const res = await call(signedRequest("POST", "/v1/deactivate", {
      licenseKey: key, hardwareHash: hw(7), platform: "linux",
    }));
    expect(res.status).toBe(400);
  });

  it("every v2 response announces the server version", async () => {
    const res = await worker.fetch(
      new Request("https://license.diskgenie.test/v1/health"),
      env as unknown as Env,
      ctx,
    );
    expect(res.headers.get("x-db-license-server")).toBe("diskgenie/3");
  });

  it("validate on an unknown key is audited (v1 gap)", async () => {
    const res = await call(signedRequest("POST", "/v1/validate", {
      licenseKey: "DB" + "1".repeat(20), hardwareHash: hw(1), platform: "windows",
    }));
    expect(res.status).toBe(404);
    const rows = await env.DB.prepare(
      "SELECT reason FROM audit_events WHERE reason = 'KEY_NOT_FOUND'",
    ).all<{ reason: string }>();
    expect(rows.results.length).toBe(1);
  });
});
