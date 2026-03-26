/**
 * Same shape as PHP `dn_maketoken`: token = `YYMM_user6` + `:` + first 6 hex chars of
 * `md5(YYMM_user6 + ':' + secret)`. No path/query involved in verification.
 *
 * `YYMM` (before the first `_`) is expiry: valid until 00:00 UTC on the first day of the
 * next calendar month (e.g. `2606` → through June 2026).
 */
import md5 from "npm:md5";

export type VerifyTokenResult = {
  ok: boolean;
  reason?: string;
  /** Logging only; never includes the secret. */
  debug?: Record<string, unknown>;
};

export function verifyToken(token: string, secret: string): VerifyTokenResult {
  const colon = token.lastIndexOf(":");
  if (colon < 0) return { ok: false, reason: "missing ':'" };

  const sig = token.slice(colon + 1);
  const payload = token.slice(0, colon);
  if (sig.length !== 6 || !/^[0-9a-fA-F]{6}$/.test(sig)) {
    return { ok: false, reason: "need 6 hex chars after ':'", debug: { sig } };
  }
  if (!payload) return { ok: false, reason: "empty payload before ':'" };

  const u = payload.indexOf("_");
  if (u < 0) {
    return {
      ok: false,
      reason: "payload needs YYMM before first '_'",
      debug: { payload },
    };
  }

  const yymm = payload.slice(0, u);
  if (!/^\d{4}$/.test(yymm)) {
    return { ok: false, reason: "YYMM must be 4 digits", debug: { yymm } };
  }
  const yy = Number(yymm.slice(0, 2));
  const mm = Number(yymm.slice(2, 4));
  if (mm < 1 || mm > 12) {
    return { ok: false, reason: "bad month in YYMM", debug: { yymm } };
  }

  // First instant this token is invalid = first day of month after YYMM (UTC).
  const expiresAt = Date.UTC(2000 + yy, mm, 1, 0, 0, 0, 0);
  if (Date.now() >= expiresAt) {
    return {
      ok: false,
      reason: `expired (YYMM ${yymm})`,
      debug: {
        payload,
        expiresExclusiveUtc: new Date(expiresAt).toISOString(),
      },
    };
  }

  const hash = md5(`${payload}:${secret}`);
  const expectedSig = hash.slice(0, 6);
  const debug: Record<string, unknown> = {
    payload,
    sig,
    yymm,
    expiresExclusiveUtc: new Date(expiresAt).toISOString(),
    expectedSig,
    md5Full: hash,
    baseForHash: `${payload}:***`,
  };

  if (sig.toLowerCase() !== expectedSig.toLowerCase()) {
    return { ok: false, reason: "signature mismatch", debug };
  }
  return { ok: true, debug };
}
