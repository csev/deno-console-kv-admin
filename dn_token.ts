/**
 * Same shape as PHP `dn_maketoken`: token = `YYMM_user6` + `:` + first 6 hex chars of
 * `md5(YYMM_user6 + ':' + secret)`. No path/query involved in verification.
 *
 * `YYMM` (before the first `_`) is expiry: valid until 00:00 UTC on the first day of the
 * next calendar month (e.g. `2606` → through June 2026).
 */
import { createHash } from "node:crypto";

export type VerifyTokenResult = {
  ok: boolean;
  reason?: string;
  debug?: Record<string, unknown>;
};

export function verifyToken(token: string, secret: string): VerifyTokenResult {
  const debug: Record<string, unknown> = { token };

  const colon = token.indexOf(":");
  if (colon < 1) return { ok: false, reason: "missing colon", debug };

  const payload = token.slice(0, colon);
  const sig = token.slice(colon + 1);
  debug.payload = payload;
  debug.sig = sig;

  if (!/^[0-9a-f]{6}$/i.test(sig)) {
    return { ok: false, reason: "invalid signature format", debug };
  }

  const underscore = payload.indexOf("_");
  if (underscore < 4) {
    return { ok: false, reason: "invalid payload format", debug };
  }

  const yymm = payload.slice(0, underscore);
  if (!/^\d{4}$/.test(yymm)) {
    return { ok: false, reason: "invalid date format", debug };
  }

  const yy = Number(yymm.slice(0, 2));
  const mm = Number(yymm.slice(2, 4));
  if (mm < 1 || mm > 12) {
    return { ok: false, reason: "invalid month", debug };
  }

  const expiresAt = Date.UTC(2000 + yy, mm, 1);
  debug.expiresAt = new Date(expiresAt).toISOString();

  if (Date.now() >= expiresAt) {
    return { ok: false, reason: "expired", debug };
  }

  const expected = createHash("md5")
    .update(`${payload}:${secret}`)
    .digest("hex")
    .slice(0, 6);

  debug.expectedSig = expected;

  if (sig.toLowerCase() !== expected) {
    return { ok: false, reason: "signature mismatch", debug };
  }

  return { ok: true, debug };
}