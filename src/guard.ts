/**
 * Request authentication (layer L2): every app-facing route runs through
 * `verifyAppRequest` — HMAC-SHA256 over (timestamp, nonce, method, path,
 * sha256(body)) with the shared CLIENT_REQUEST_SECRET, ±300 s window,
 * single-use nonce. Admin routes use `verifyAdmin` (bearer key,
 * constant-time compare).
 *
 * No CORS headers are ever emitted — browsers cannot call this API
 * cross-origin. The USER-AGENT is additionally pinned to the client's
 * (friction only — the real boundary is the Ed25519 signature on
 * responses).
 */
import type { Env } from "./types";
import { hmacHex, sha256Hex, timingSafeEqual } from "./crypto";

const CLOCK_WINDOW_S = 300;

/** The client's pinned User-Agent (friction layer — the real boundary is
 *  the Ed25519 signature on responses).
 *
 *  RENAME COMPAT WINDOW (DiskBytes → DiskGenie, 2026-10): the deployed
 *  worker validates the OLD value, and shipped app builds still send it;
 *  renamed builds send the new one. Accept BOTH until every install has
 *  updated, then retire the old entry. */
const CLIENT_UAS = new Set([
  "DiskGenie-License-Client/1",
  "DiskBytes-License-Client/1",
]);

export type GuardFailure =
  | "BAD_SIGNATURE"
  | "BAD_TIMESTAMP"
  | "REPLAYED"
  | "BAD_UA"
  | "BAD_ADMIN_KEY"
  /** Token-level: a verified-signature token minted for another
   *  product (aud mismatch) — 403 (see tokens.ts checkTokenClaims). */
  | "BAD_AUDIENCE";

export interface AppRequest {
  body: string;
  /** Verified timestamp (unix ms) once the guard passes. */
  timestamp: number;
}

/** Verify app request auth; returns the failure code or null when OK. */
export async function verifyAppRequest(
  env: Env,
  request: Request,
  pathname: string,
  rawBody: string,
): Promise<{ ok: AppRequest } | { fail: GuardFailure }> {
  const ua = request.headers.get("user-agent") ?? "";
  if (!CLIENT_UAS.has(ua)) return { fail: "BAD_UA" };

  const ts = request.headers.get("x-db-timestamp") ?? "";
  const nonce = request.headers.get("x-db-nonce") ?? "";
  const sig = request.headers.get("x-db-signature") ?? "";
  if (!/^\d{1,15}$/.test(ts) || !/^[0-9a-f]{32}$/.test(nonce) || !/^[0-9a-f]{64}$/.test(sig)) {
    return { fail: "BAD_SIGNATURE" };
  }
  const tsMs = Number.parseInt(ts, 10);
  const nowMs = Date.now();
  const driftS = Math.abs(nowMs - tsMs) / 1000;
  if (driftS > CLOCK_WINDOW_S) return { fail: "BAD_TIMESTAMP" };

  const bodyHash = await sha256Hex(rawBody);
  const method = request.method.toUpperCase();
  const expected = await hmacHex(
    env.CLIENT_REQUEST_SECRET,
    `${ts}.${nonce}.${method}.${pathname}.${bodyHash}`,
  );
  if (!timingSafeEqual(expected, sig)) return { fail: "BAD_SIGNATURE" };
  return { ok: { body: rawBody, timestamp: tsMs } };
}

/** Admin guard: `Authorization: Bearer <ADMIN_API_KEY>`. */
export function verifyAdmin(env: Env, request: Request): GuardFailure | null {
  const auth = request.headers.get("authorization") ?? "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token || !timingSafeEqual(token, env.ADMIN_API_KEY)) return "BAD_ADMIN_KEY";
  return null;
}
