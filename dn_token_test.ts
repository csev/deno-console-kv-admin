import { assert, assertEquals } from "jsr:@std/assert@1";
import { createHash } from "node:crypto";
import { verifyToken } from "./dn_token.ts";

const secret = "42";

function md5Prefix6(payload: string, s: string): string {
  return createHash("md5").update(`${payload}:${s}`).digest("hex").slice(0, 6);
}

function tokenFor(payload: string, s: string = secret): string {
  return `${payload}:${md5Prefix6(payload, s)}`;
}

Deno.test("verifyToken: accepts well-formed token with future YYMM", () => {
  const payload = "9912_hello";
  const token = tokenFor(payload);
  const r = verifyToken(token, secret);
  assert(r.ok, r.reason);
  assertEquals(r.debug?.payload, payload);
});

Deno.test("verifyToken: rejects missing colon", () => {
  const r = verifyToken("9912_hellonoColon", secret);
  assertEquals(r.ok, false);
  assertEquals(r.reason, "missing colon");
});

Deno.test("verifyToken: rejects empty payload before colon", () => {
  const r = verifyToken(":abcdef", secret);
  assertEquals(r.ok, false);
  assertEquals(r.reason, "missing colon");
});

Deno.test("verifyToken: rejects non-hex signature", () => {
  const r = verifyToken("9912_hello:GGGGGG", secret);
  assertEquals(r.ok, false);
  assertEquals(r.reason, "invalid signature format");
});

Deno.test("verifyToken: rejects wrong signature", () => {
  const r = verifyToken("9912_hello:000000", secret);
  assertEquals(r.ok, false);
  assertEquals(r.reason, "signature mismatch");
});

Deno.test("verifyToken: rejects wrong secret", () => {
  const token = tokenFor("9912_hello", "42");
  const r = verifyToken(token, "other-secret");
  assertEquals(r.ok, false);
  assertEquals(r.reason, "signature mismatch");
});

Deno.test("verifyToken: rejects expired YYMM", () => {
  const payload = "0001_x";
  const token = tokenFor(payload);
  const r = verifyToken(token, secret);
  assertEquals(r.ok, false);
  assertEquals(r.reason, "expired");
});

Deno.test("verifyToken: rejects invalid month", () => {
  const payload = "9920_x";
  const token = tokenFor(payload);
  const r = verifyToken(token, secret);
  assertEquals(r.ok, false);
  assertEquals(r.reason, "invalid month");
});

Deno.test("verifyToken: rejects payload without underscore in expected position", () => {
  const r = verifyToken("123_x:abcdef", secret);
  assertEquals(r.ok, false);
  assertEquals(r.reason, "invalid payload format");
});

Deno.test("verifyToken: rejects non-digit YYMM", () => {
  const r = verifyToken("99ab_zz:abcdef", secret);
  assertEquals(r.ok, false);
  assertEquals(r.reason, "invalid date format");
});
