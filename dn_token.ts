/**
 * Mirrors PHP token construction used with `dn_maketoken($user, $secret)`:
 *
 * ```php
 * function dn_maketoken($user, $secret) {
 *     $expire = dn_getexpire();
 *     $base = $expire . '_' . substr($user, 0, 6) . ':' . $secret;
 *     $sig = md5($base);
 *     $pw = $expire . '_' . substr($user, 0, 6) . ':' . substr($sig, 0, 6);
 *     return($pw);
 * }
 * ```
 *
 * Verification (no URL/path user): split on the last `:`. The right side is the 6-hex
 * signature; the left side is the signed payload. Recompute `md5(left + ':' + secret)` and
 * compare the first 6 hex characters to the signature.
 *
 * Expiry: the substring before the first `_` in the signed payload is `YYMM` (e.g. `2606` =
 * June 2026). The token is rejected when current time is ≥ 00:00 UTC on the first day of the
 * month after `YYMM` (not valid after the end of that month).
 */
import md5 from "npm:md5";

/** First instant (UTC) when a token with expiry YYMM is no longer valid. */
export function tokenExpiryExclusiveUtc(yy: number, mm: number): number {
  const year = 2000 + yy;
  const monthIndex = mm - 1; // June → 5
  return Date.UTC(year, monthIndex + 1, 1, 0, 0, 0, 0);
}

/**
 * `signedPayload` is `YYMM_rest` (e.g. `2606_dca272`). Returns failure if missing `_`,
 * bad YYMM, or now ≥ first day of next month UTC.
 */
export function checkSignedPayloadExpiry(
  signedPayload: string,
  nowMs: number = Date.now(),
): { ok: true; yy: number; mm: number; expireYYMM: string } | { ok: false; reason: string } {
  const usc = signedPayload.indexOf("_");
  if (usc < 0) {
    return {
      ok: false,
      reason:
        "signed payload has no '_' (cannot read YYMM expire prefix before first '_')",
    };
  }
  const expireYYMM = signedPayload.slice(0, usc);
  if (!/^\d{4}$/.test(expireYYMM)) {
    return {
      ok: false,
      reason:
        `expire prefix must be 4 digits YYMM (got ${JSON.stringify(expireYYMM)})`,
    };
  }
  const yy = Number(expireYYMM.slice(0, 2));
  const mm = Number(expireYYMM.slice(2, 4));
  if (mm < 1 || mm > 12) {
    return {
      ok: false,
      reason: `invalid month in YYMM ${JSON.stringify(expireYYMM)} (MM must be 01–12)`,
    };
  }
  const boundary = tokenExpiryExclusiveUtc(yy, mm);
  if (nowMs >= boundary) {
    const until = new Date(boundary).toISOString();
    return {
      ok: false,
      reason:
        `token expired: YYMM ${expireYYMM} is not valid after ${until} UTC (end of that calendar month)`,
    };
  }
  return { ok: true, yy, mm, expireYYMM };
}

/** Same as PHP `substr($user, 0, 6)` for ASCII user ids. */
function userPrefix6(user: string): string {
  return user.slice(0, 6);
}

/** Build a token (for tests or tooling); pass `expire` from PHP `dn_getexpire()`. */
export function dnMakeToken(user: string, secret: string, expire: string): string {
  const u6 = userPrefix6(user);
  const base = `${expire}_${u6}:${secret}`;
  const sig = md5(base);
  return `${expire}_${u6}:${sig.slice(0, 6)}`;
}

export type TokenParts = {
  /** Token substring before the last ':' (e.g. `expire_userPrefix`). */
  signedPayload: string;
  sig6FromToken: string;
  /** Four-digit YYMM from before first `_`. */
  expireYYMM?: string;
  /** ISO time (UTC) when this token becomes invalid (first moment of following month). */
  expiresExclusiveUtc?: string;
  /** `${signedPayload}:***` — secret not logged */
  basePattern: string;
  md5Full?: string;
  expectedSig6?: string;
};

export type TokenVerifyDetail = {
  ok: boolean;
  reason?: string;
  parts?: TokenParts;
};

/**
 * Verify token using only `token` and server `secret` (identity is encoded in the token).
 */
export function dnVerifyTokenDetail(token: string, secret: string): TokenVerifyDetail {
  const colon = token.lastIndexOf(":");
  if (colon < 0) {
    return {
      ok: false,
      reason: "token has no ':' (expected …:sig6)",
    };
  }

  const sig6FromToken = token.slice(colon + 1);
  if (sig6FromToken.length !== 6 || !/^[0-9a-fA-F]{6}$/.test(sig6FromToken)) {
    return {
      ok: false,
      reason:
        `signature part after ':' must be exactly 6 hex chars (got length ${sig6FromToken.length}, value ${JSON.stringify(sig6FromToken)})`,
    };
  }

  const signedPayload = token.slice(0, colon);
  if (signedPayload.length === 0) {
    return {
      ok: false,
      reason: "nothing before ':' to sign (empty signed payload)",
    };
  }

  const expiry = checkSignedPayloadExpiry(signedPayload);
  if (!expiry.ok) {
    return {
      ok: false,
      reason: expiry.reason,
      parts: {
        signedPayload,
        sig6FromToken,
        basePattern: `${signedPayload}:***`,
      },
    };
  }

  const base = `${signedPayload}:${secret}`;
  const md5Full = md5(base);
  const expectedSig6 = md5Full.slice(0, 6);
  const basePattern = `${signedPayload}:***`;
  const expiresExclusiveUtc = new Date(
    tokenExpiryExclusiveUtc(expiry.yy, expiry.mm),
  ).toISOString();

  const parts: TokenParts = {
    signedPayload,
    sig6FromToken,
    expireYYMM: expiry.expireYYMM,
    expiresExclusiveUtc,
    basePattern,
    md5Full,
    expectedSig6,
  };

  if (sig6FromToken.toLowerCase() !== expectedSig6.toLowerCase()) {
    return {
      ok: false,
      reason:
        `MD5 prefix mismatch: token sig ${JSON.stringify(sig6FromToken)} !== first 6 of md5(${JSON.stringify(basePattern)}) which is ${JSON.stringify(expectedSig6)}`,
      parts,
    };
  }

  return { ok: true, parts };
}

export function dnVerifyToken(token: string, secret: string): boolean {
  return dnVerifyTokenDetail(token, secret).ok;
}
