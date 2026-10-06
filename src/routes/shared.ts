/**
 * Shared route plumbing: response shaping, guard-failure mapping, body
 * parsing + shape validation for the v2 DeviceClaim, and the per-route
 * rate limits. Extracted from the per-route duplication in v1 so the
 * wire contract lives in exactly one place per concern.
 */
import type { Env, DeviceClaim } from "../types";
import { Db, SlotTakenError } from "../db";
import { verifyAppRequest, type GuardFailure } from "../guard";
import { ipHashOf } from "../crypto";

export const json = (status: number, body: object): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
      "x-db-license-server": "diskgenie/3",
    },
  });

export const fail = (status: number, code: string, message: string): Response =>
  json(status, { ok: false, code, message });

export const GUARD_STATUS: Record<GuardFailure, number> = {
  BAD_SIGNATURE: 401,
  BAD_TIMESTAMP: 401,
  REPLAYED: 401,
  BAD_UA: 403,
  BAD_ADMIN_KEY: 401,
  BAD_AUDIENCE: 403,
};

export function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

/** Request bodies are tiny (≤ a few KB); anything bigger is abuse. */
export const MAX_BODY_BYTES = 16_384;

/**
 * The app-facing guard: read the body ONCE (Workers bodies are
 * single-read), verify the HMAC headers, parse the JSON — one step.
 * Guard rejections are audited (denied + reason) exactly like v1.
 */
export async function verifyAndParse<T extends object>(
  env: Env,
  request: Request,
  path: string,
): Promise<{ ok: { body: T; ipHash: string } } | { fail: Response }> {
  const raw = await request.text();
  if (raw.length > MAX_BODY_BYTES) {
    return { fail: fail(400, "BAD_REQUEST", "Request body too large.") };
  }
  const guard = await verifyAppRequest(env, request, path, raw);
  if ("fail" in guard) {
    const db = new Db(env.DB);
    await db.audit({
      event: "denied",
      reason: guard.fail,
      ipHash: await ipHashOf(env, request.headers.get("cf-connecting-ip")),
      now: nowSec(),
    });
    return { fail: fail(GUARD_STATUS[guard.fail], guard.fail, "Request rejected.") };
  }
  try {
    const body = JSON.parse(raw) as T;
    const ipHash = await ipHashOf(env, request.headers.get("cf-connecting-ip"));
    return { ok: { body, ipHash } };
  } catch {
    return { fail: fail(400, "BAD_REQUEST", "Malformed request body.") };
  }
}

/** Normalize a license key claim: uppercase, alphanumerics only. */
export function normalizeKeyClaim(raw: unknown): string {
  return (typeof raw === "string" ? raw : "").toUpperCase().replace(/[^0-9A-Z]/g, "");
}

export function isValidPlatform(p: unknown): p is "windows" | "macos" {
  return p === "windows" || p === "macos";
}

const HEX64 = /^[0-9a-f]{64}$/;
const SAFE_TEXT = /^[\x20-\x7e]{0,120}$/; // printable ASCII, ≤120 chars
const UUID36 = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const ARCHES = new Set(["x86_64", "aarch64", "x86", "arm"]);

/** Strip control characters (CPUID brand strings carry NUL padding;
 * SMBIOS strings can carry stray \r\n) and collapse runs of spaces —
 * v2 dropped the whole field on the first control char, which is why
 * "cpu brand doesn't seem to work" on VM/QEMU-style brand strings. */
const cleanText = (v: string): string =>
  v
    .replace(/[\x00-\x1f\x7f]/g, " ")
    .replace(/ {2,}/g, " ")
    .trim()
    .slice(0, 120);

/**
 * Validate + sanitize the v3 DeviceClaim (all optional fields — older
 * clients simply omit them). Unknown/garbage fields are dropped, text
 * fields are length- and charset-capped (control chars cleaned, not
 * fatal), hex fields are strict, arch is a whitelist, numeric fields
 * are range-clamped. Returns null when the claim body itself is
 * malformed.
 */
export function sanitizeClaim(
  raw: unknown,
  platform: "windows" | "macos",
  hardwareHash: string,
): DeviceClaim | null {
  if (raw === null || typeof raw !== "object") return null;
  const c = raw as Record<string, unknown>;
  const text = (v: unknown): string | undefined => {
    if (typeof v !== "string") return undefined;
    const cleaned = cleanText(v);
    return cleaned.length > 0 && SAFE_TEXT.test(cleaned) ? cleaned : undefined;
  };
  const hex64 = (v: unknown): string | undefined => {
    if (typeof v !== "string") return undefined;
    const lower = v.toLowerCase();
    return HEX64.test(lower) ? lower : undefined;
  };
  const uuid = (v: unknown): string | undefined => {
    if (typeof v !== "string") return undefined;
    const lower = cleanText(v).toLowerCase();
    return UUID36.test(lower) ? lower : undefined;
  };
  let ramMb: number | undefined;
  if (typeof c.ramMb === "number" && Number.isFinite(c.ramMb)) {
    ramMb = Math.min(Math.max(Math.round(c.ramMb), 0), 1_048_576);
  }
  let cpuCores: number | undefined;
  if (typeof c.cpuCores === "number" && Number.isFinite(c.cpuCores)) {
    cpuCores = Math.min(Math.max(Math.round(c.cpuCores), 0), 1024);
  }
  const arch = typeof c.arch === "string" && ARCHES.has(c.arch) ? c.arch : undefined;
  return {
    hardwareHash,
    platform,
    hostname: text(c.hostname),
    osVersion: text(c.osVersion),
    appVersion: text(c.appVersion),
    compMachine: hex64(c.compMachine),
    compVolume: hex64(c.compVolume),
    compCpu: hex64(c.compCpu),
    cpuBrand: text(c.cpuBrand),
    ramMb,
    machineModel: text(c.machineModel),
    baseboardSerial: text(c.baseboardSerial),
    firmwareUuid: uuid(c.firmwareUuid),
    biosVersion: text(c.biosVersion),
    cpuCores,
    arch,
    compBoard: hex64(c.compBoard),
    compFirmware: hex64(c.compFirmware),
  };
}

/** Per-route rate limit policy. Each policy names its OWN override var —
 * tuning activate must never silently tighten validate (a legit
 * validate cadence is 24 h per device + manual "Validate now" clicks). */
export interface RatePolicy {
  varName: "RATE_ACTIVATE_KEY_PER_HR" | "RATE_VALIDATE_KEY_PER_HR";
  keyLimit: number;
  windowSec: number;
  ipLimit?: number;
}

export const ACTIVATE_RATE: RatePolicy = { varName: "RATE_ACTIVATE_KEY_PER_HR", keyLimit: 10, windowSec: 3_600, ipLimit: 30 };
export const VALIDATE_RATE: RatePolicy = { varName: "RATE_VALIDATE_KEY_PER_HR", keyLimit: 60, windowSec: 3_600 };
export const DEACTIVATE_RATE: RatePolicy = { varName: "RATE_ACTIVATE_KEY_PER_HR", keyLimit: 10, windowSec: 3_600 };

/** Read the policy's key-limit override (Env var; fallback = default). */
export function keyLimitFor(env: Env, policy: RatePolicy): number {
  const n = Number.parseInt(env[policy.varName] ?? "", 10);
  return Number.isFinite(n) && n > 0 ? n : policy.keyLimit;
}

/**
 * Consume the per-key (and per-IP when configured) buckets. Returns a
 * 429 Response when exhausted, null when the request may proceed.
 */
export async function checkRate(
  db: Db,
  env: Env,
  policy: RatePolicy,
  bucketId: string,
  ipHash: string,
  now: number,
): Promise<Response | null> {
  const keyLimit = keyLimitFor(env, policy);
  const keyOk = await db.rateConsume(`rl:${bucketId}`, keyLimit, policy.windowSec, now);
  if (!keyOk) {
    return fail(429, "RATE_LIMITED", "Too many attempts — wait a minute and try again.");
  }
  if (policy.ipLimit !== undefined) {
    const ipOk = await db.rateConsume(`rl:ip:${ipHash}`, policy.ipLimit, policy.windowSec, now);
    if (!ipOk) {
      return fail(429, "RATE_LIMITED", "Too many attempts from this network — try again later.");
    }
  }
  return null;
}

/** Map a SlotTakenError to the 409 contract. */
export function isSlotTaken(err: unknown): boolean {
  return err instanceof SlotTakenError;
}

export { verifyAppRequest };
