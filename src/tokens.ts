/**
 * Token minting + response shaping. All timing inputs are unix SECONDS.
 * The client (Rust) independently re-verifies signature, hw, plat, key
 * hash, exp and lexp — this module is the issuance side only.
 */
import type { Env, EntitlementResponse, TokenPayload } from "./types";
import { randomHex, signToken } from "./crypto";
import { sha256Hex } from "./crypto";

/** The product this server issues tokens for — the `aud` (audience)
 *  claim. A token minted for another product (or a lookalike licensing
 *  server reusing this claim shape) must not verify here. */
export const TOKEN_AUDIENCE = "diskgenie";

/** The kid (key id) of the CURRENT signing seed — bumped at every seed
 *  rotation (README §9); the deployed fleet then carries a mix of kids
 *  during the overlap window, which is exactly what the registry below
 *  is for. */
export const CURRENT_KID = 1;

/** kid → signing seed (the KID_REGISTRY). Today exactly one key is live:
 *  kid 1 IS `LICENSE_SIGNING_PRIVATE_KEY`. At a rotation you add the
 *  incoming seed under kid 2, keep kid 1 until every 14-day token it
 *  signed has expired, then retire the kid-1 entry — verification picks
 *  the key by the token's claim instead of assuming a single seed. */
export function kidRegistry(env: Env): Map<number, string> {
  return new Map([[CURRENT_KID, env.LICENSE_SIGNING_PRIVATE_KEY]]);
}

/**
 * Claim check for the verification paths (/v1/verify + tests): tokens
 * minted BEFORE kid/aud existed (the deployed fleet — the compat
 * window) verify unchanged, but a token that CARRIES the claims must
 * carry the right ones: `aud` must be this product, `kid` must be a
 * registered key id. Returns the error code that applies, or "ok".
 */
export function checkTokenClaims(env: Env, payload: object): "ok" | "BAD_AUDIENCE" | "BAD_SIGNATURE" {
  const p = payload as { kid?: unknown; aud?: unknown };
  if (p.aud !== undefined && p.aud !== TOKEN_AUDIENCE) return "BAD_AUDIENCE";
  if (p.kid !== undefined && !(typeof p.kid === "number" && kidRegistry(env).has(p.kid))) {
    return "BAD_SIGNATURE";
  }
  return "ok";
}

/** Token grace window (seconds) — TOKEN_TTL_DAYS, default 14 days. */
export function tokenTtlSeconds(env: Env): number {
  const days = Number.parseInt(env.TOKEN_TTL_DAYS ?? "14", 10);
  const safe = Number.isFinite(days) && days > 0 && days <= 90 ? days : 14;
  return safe * 86_400;
}

/** Mint a signed token for a validated (license, device) pair. */
export async function mintToken(
  env: Env,
  license: {
    id: number;
    keyHash: string;
    tier: "yearly" | "lifetime";
    customerName: string;
    customerEmail: string;
    expiresAt: number | null;
  },
  device: { platform: "windows" | "macos"; hardwareHash: string },
  now: number,
): Promise<string> {
  const payload: TokenPayload = {
    iss: "db-license",
    ver: 1,
    // Rotation groundwork: every NEWLY minted token names its signing
    // key (kid) and its product (aud). Verification accepts tokens
    // without them (the deployed fleet's compat window) but enforces the
    // values when present — see checkTokenClaims.
    kid: CURRENT_KID,
    aud: TOKEN_AUDIENCE,
    jti: randomHex(16),
    iat: now,
    exp: now + tokenTtlSeconds(env),
    key: license.keyHash,
    tier: license.tier,
    name: license.customerName,
    email: license.customerEmail,
    hw: device.hardwareHash,
    plat: device.platform,
    lexp: license.expiresAt,
  };
  return signToken(env.LICENSE_SIGNING_PRIVATE_KEY, payload);
}

/** Build the app-facing success body. */
export function entitlementResponse(
  token: string,
  license: {
    tier: "yearly" | "lifetime";
    customerName: string;
    customerEmail: string;
    expiresAt: number | null;
    keyLast4: string;
  },
  device: { platform: "windows" | "macos"; activatedAt: number; lastSeenAt: number },
): EntitlementResponse {
  return {
    ok: true,
    token,
    license: {
      tier: license.tier,
      name: license.customerName,
      email: license.customerEmail,
      expiresAt: license.expiresAt,
      last4: license.keyLast4,
    },
    device,
  };
}

/** sha256(key) hex — the ONLY form of the key that persists. */
export function keyHashOf(normalizedKey: string): Promise<string> {
  return sha256Hex(normalizedKey);
}
