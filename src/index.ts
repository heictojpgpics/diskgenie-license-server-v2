/**
 * DiskGenie license server — Worker entry (router), v3.
 *
 * App routes (request-HMAC auth, UA pinned):
 *   POST /v1/activate     bind device + mint token (rate-limited)
 *   POST /v1/validate     24 h revalidation + fresh token (full device
 *                         claim — the v2 fix that stopped fact-wiping)
 *   POST /v1/deactivate   free this device's slot
 *   POST /v1/verify       debug: verify a token against the public key
 *                         (request-HMAC auth; returns the payload only)
 *
 * Public:
 *   GET  /v1/health       liveness
 *
 * Admin (bearer):
 *   /v1/admin/*           key generation + management + lookup +
 *                         transfer + refund + device census (routes/admin.ts)
 *
 * v3: deeper hardware claims (baseboard serial, firmware UUID, BIOS
 * build, core count, arch + their component hashes) with control-char
 * cleaning so CPUID-brand strings with NUL padding survive sanitizing.
 */
import { handleActivate } from "./routes/activate";
import { handleValidate } from "./routes/validate";
import { handleDeactivate } from "./routes/deactivate";
import { handleAdmin } from "./routes/admin";
import { verifyAppRequest } from "./guard";
import { publicKeyFromSeed, toHex, verifyToken } from "./crypto";
import { ensureSchema } from "./schema";
import { checkTokenClaims } from "./tokens";
import type { Env } from "./types";
import { fail, GUARD_STATUS, json, MAX_BODY_BYTES } from "./routes/shared";
import { Db } from "./db";

// Memoized public-key derivation (v3.1): deriving the Ed25519 public
// key from the seed is deterministic and the seed is immutable per
// deploy, so each isolate derives it ONCE — the same per-isolate memo
// pattern as crypto.ts's IP-hash salt. (The /v1/verify handler used to
// re-derive it on every call: pure repeated CPU cost.) The cache is
// keyed on the seed so a swapped secret (rotation) re-derives.
let pubKeyCache: { seed: string; hex: string } | null = null;
async function publicKeyHex(seedHex: string): Promise<string> {
  if (pubKeyCache?.seed !== seedHex) {
    pubKeyCache = { seed: seedHex, hex: toHex(await publicKeyFromSeed(seedHex)) };
  }
  return pubKeyCache.hex;
}

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    // Reject cross-origin browser calls by construction: no CORS headers
    // are ever added; the app client is not a browser.
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/$/, "");

    try {
      // Self-healing additive schema (v3): the deploy pipeline ships
      // code faster than migrations; ensure the v3 columns exist before
      // any route touches them (per-isolate latch — see src/schema.ts).
      await ensureSchema(env.DB);
      if (request.method === "GET" && path === "/v1/health") {
        return json(200, { ok: true, service: "diskgenie-license", version: 3, time: Math.floor(Date.now() / 1000) });
      }
      if (path.startsWith("/v1/admin")) {
        return handleAdmin(env, request, url);
      }
      if (request.method === "POST" && path === "/v1/activate") {
        return handleActivate(env, request);
      }
      if (request.method === "POST" && path === "/v1/validate") {
        return handleValidate(env, request);
      }
      if (request.method === "POST" && path === "/v1/deactivate") {
        return handleDeactivate(env, request);
      }
      if (request.method === "POST" && path === "/v1/verify") {
        // Debug endpoint (still HMAC-authenticated): POST { token } → payload.
        // Same hardening as the app routes: body-size guard BEFORE anything
        // else, and a malformed JSON body is a 400 (it used to escape as a
        // 500 SERVER_ERROR from the outer catch — a client bug, not a
        // server fault). Nonce consumption + the UA compat window are
        // unchanged.
        const raw = await request.text();
        if (raw.length > MAX_BODY_BYTES) {
          return fail(400, "BAD_REQUEST", "Request body too large.");
        }
        const guard = await verifyAppRequest(env, request, path, raw);
        if ("fail" in guard) return json(401, { ok: false, code: guard.fail, message: "Request rejected." });
        const nonce = request.headers.get("x-db-nonce") ?? "";
        if (!(await new Db(env.DB).consumeNonce(nonce, Math.floor(Date.now() / 1000)))) {
          return json(401, { ok: false, code: "REPLAYED", message: "Request rejected." });
        }
        let body: { token?: string };
        try {
          body = JSON.parse(raw) as { token?: string };
        } catch {
          return fail(400, "BAD_REQUEST", "Malformed request body.");
        }
        const pubHex = await publicKeyHex(env.LICENSE_SIGNING_PRIVATE_KEY);
        const payload = body.token ? await verifyToken(pubHex, body.token) : null;
        // kid/aud claim check (compat window): the signature verified,
        // but a token that CARRIES the rotation claims must carry the
        // right ones — aud must be this product (403 BAD_AUDIENCE), kid
        // must be a registered key id (else it is a signature-level
        // failure: the token names a key we never minted with). Legacy
        // tokens (no kid/aud — the deployed fleet) pass through.
        if (payload !== null) {
          const claims = checkTokenClaims(env, payload);
          if (claims === "BAD_AUDIENCE") {
            return fail(GUARD_STATUS.BAD_AUDIENCE, "BAD_AUDIENCE", "Token audience mismatch.");
          }
          if (claims === "BAD_SIGNATURE") {
            return json(401, { ok: false, code: "BAD_SIGNATURE", message: "Request rejected." });
          }
        }
        return json(200, { ok: true, valid: payload !== null, payload });
      }
      return json(404, { ok: false, code: "NOT_FOUND", message: "Unknown route." });
    } catch (err) {
      // Never leak stack traces; observability (wrangler tail) sees the error.
      console.error("worker error", err instanceof Error ? err.message : String(err));
      return json(500, { ok: false, code: "SERVER_ERROR", message: "License server error — try again shortly." });
    }
  },
};
