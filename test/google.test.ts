/**
 * Google id_token verifier tests — fully deterministic, ZERO egress.
 *
 * Wiring per BUILD_PLAN finalization decision #8:
 *   • jose generateKeyPair('RS256') + exportJWK to mint a local signing keypair.
 *   • StaticJwksSource over the PUBLIC jwk (kid set) — the verifier selects by kid.
 *   • jose SignJWT to forge id_tokens; a fixed Clock pins exp checks.
 *
 * The real FetchJwksSource is NEVER constructed here: no network is touched.
 *
 * Covers the happy path (-> google-prefixed sub, normalized email, displayName)
 * and every GoogleFailureReason: untrusted_audience, untrusted_issuer, expired,
 * email_unverified, missing_email, bad_signature (DIFFERENT key not in the JWKS),
 * and malformed ('not.a.jwt').
 */

import { describe, expect, it, beforeAll } from "vitest";
import {
  generateKeyPair,
  exportJWK,
  SignJWT,
  type JWK,
  // jose v6 dropped the `KeyLike` alias; `generateKeyPair` yields jose's
  // `CryptoKey` type (the WebCrypto key), which `SignJWT.sign` accepts.
  type CryptoKey as JoseCryptoKey,
} from "jose";

import { createGoogleVerifier } from "../src/google.js";
import { StaticJwksSource } from "../src/adapters/static-jwks.js";
import type { Clock, Jwk } from "../src/ports.js";

// ── Fixtures ─────────────────────────────────────────────────────────────────

const KID = "test-kid-1";
const ISSUER = "https://accounts.google.com";
const AUDIENCE = "client-id-under-test.apps.googleusercontent.com";

// A fixed point in (real-ish) time, in epoch SECONDS, for deterministic exp.
const NOW_SEC = 1_700_000_000;

/** Fixed Clock pinned to NOW_SEC (the source feeds clock.now() ms to jose). */
const fixedClock: Clock = { now: () => NOW_SEC * 1000 };

// Trusted keypair (its public half goes into the JWKS).
let privateKey: JoseCryptoKey;
let publicJwk: Jwk;
// An UNtrusted keypair whose public half is NOT in the JWKS (for bad_signature).
let foreignPrivateKey: JoseCryptoKey;

beforeAll(async () => {
  const trusted = await generateKeyPair("RS256", { extractable: true });
  privateKey = trusted.privateKey;
  const jwk: JWK = await exportJWK(trusted.publicKey);
  jwk.kid = KID;
  jwk.alg = "RS256";
  jwk.use = "sig";
  publicJwk = jwk as Jwk;

  const foreign = await generateKeyPair("RS256", { extractable: true });
  foreignPrivateKey = foreign.privateKey;
});

/** Build a verifier over the trusted JWKS + fixed clock. */
function buildVerifier(overrides?: {
  allowedAudiences?: string[];
  allowedIssuers?: string[];
}) {
  const jwks = new StaticJwksSource([publicJwk]);
  return createGoogleVerifier(
    { jwks, clock: fixedClock },
    {
      allowedAudiences: overrides?.allowedAudiences ?? [AUDIENCE],
      allowedIssuers: overrides?.allowedIssuers,
    },
  );
}

interface ClaimOverrides {
  iss?: string;
  aud?: string;
  sub?: string;
  email?: string | undefined;
  email_verified?: unknown;
  name?: string | undefined;
  exp?: number;
  iat?: number;
}

/** Forge an id_token signed by `key` (defaults to the trusted private key). */
async function signToken(
  claims: ClaimOverrides = {},
  key: JoseCryptoKey = privateKey,
  kid: string = KID,
): Promise<string> {
  const payload: Record<string, unknown> = {};
  if (claims.email !== undefined) payload.email = claims.email;
  if ("email_verified" in claims) payload.email_verified = claims.email_verified;
  else payload.email_verified = true;
  if (claims.name !== undefined) payload.name = claims.name;

  const exp = claims.exp ?? NOW_SEC + 3600;
  const iat = claims.iat ?? NOW_SEC - 60;

  return new SignJWT(payload)
    .setProtectedHeader({ alg: "RS256", kid })
    .setSubject(claims.sub ?? "google-sub-1234567890")
    .setIssuer(claims.iss ?? ISSUER)
    .setAudience(claims.aud ?? AUDIENCE)
    .setIssuedAt(iat)
    .setExpirationTime(exp)
    .sign(key);
}

// ── Happy path ───────────────────────────────────────────────────────────────

describe("Google verifier — happy path", () => {
  it("verifies a well-formed token -> google:<sub>, normalized email, displayName", async () => {
    const verifier = buildVerifier();
    const token = await signToken({
      sub: "google-sub-1234567890",
      email: "  Person@Example.COM  ",
      email_verified: true,
      name: "Real Person",
    });

    const res = await verifier.verify(token);

    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error("expected ok");
    // providerSubject is google:<sub>, NEVER the email.
    expect(res.identity.providerSubject).toBe("google:google-sub-1234567890");
    // email is normalized (trim + lowercase).
    expect(res.identity.email).toBe("person@example.com");
    expect(res.identity.emailVerified).toBe(true);
    expect(res.identity.displayName).toBe("Real Person");
  });

  it("accepts the bare 'accounts.google.com' issuer (default issuer set)", async () => {
    const verifier = buildVerifier();
    const token = await signToken({
      iss: "accounts.google.com",
      email: "a@b.com",
      email_verified: true,
    });
    const res = await verifier.verify(token);
    expect(res.ok).toBe(true);
  });

  it("accepts email_verified as the string 'true'", async () => {
    const verifier = buildVerifier();
    const token = await signToken({ email: "a@b.com", email_verified: "true" });
    const res = await verifier.verify(token);
    expect(res.ok).toBe(true);
  });

  it("omits displayName when no name claim is present", async () => {
    const verifier = buildVerifier();
    const token = await signToken({ email: "a@b.com", email_verified: true });
    const res = await verifier.verify(token);
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error("expected ok");
    expect(res.identity.displayName).toBeUndefined();
  });
});

// ── Failure reasons (each mapped to the typed GoogleFailureReason) ───────────

describe("Google verifier — failure reasons", () => {
  it("untrusted_audience when aud is not in allowedAudiences", async () => {
    const verifier = buildVerifier({ allowedAudiences: ["the-only-allowed-aud"] });
    const token = await signToken({ aud: "some-other-aud", email: "a@b.com" });
    const res = await verifier.verify(token);
    expect(res).toEqual({ ok: false, reason: "untrusted_audience" });
  });

  it("untrusted_issuer when iss is not in allowedIssuers", async () => {
    const verifier = buildVerifier();
    const token = await signToken({ iss: "https://evil.example.com", email: "a@b.com" });
    const res = await verifier.verify(token);
    expect(res).toEqual({ ok: false, reason: "untrusted_issuer" });
  });

  it("expired when exp is in the past per the fixed Clock", async () => {
    const verifier = buildVerifier();
    const token = await signToken({
      email: "a@b.com",
      exp: NOW_SEC - 3600, // expired an hour before "now"
      iat: NOW_SEC - 7200,
    });
    const res = await verifier.verify(token);
    expect(res).toEqual({ ok: false, reason: "expired" });
  });

  it("email_unverified when email_verified is false", async () => {
    const verifier = buildVerifier();
    const token = await signToken({ email: "a@b.com", email_verified: false });
    const res = await verifier.verify(token);
    expect(res).toEqual({ ok: false, reason: "email_unverified" });
  });

  it("missing_email when no email claim is present", async () => {
    const verifier = buildVerifier();
    // email omitted entirely; email_verified true so we reach the email check.
    const token = await signToken({ email: undefined, email_verified: true });
    const res = await verifier.verify(token);
    expect(res).toEqual({ ok: false, reason: "missing_email" });
  });

  it("bad_signature when signed with a DIFFERENT key not in the JWKS", async () => {
    const verifier = buildVerifier();
    // Same kid (so key selection succeeds) but a foreign private key -> the
    // signature cannot verify against the trusted public key.
    const token = await signToken(
      { email: "a@b.com", email_verified: true },
      foreignPrivateKey,
      KID,
    );
    const res = await verifier.verify(token);
    expect(res).toEqual({ ok: false, reason: "bad_signature" });
  });

  it("malformed for a non-JWT string ('not.a.jwt')", async () => {
    const verifier = buildVerifier();
    const res = await verifier.verify("not.a.jwt");
    expect(res).toEqual({ ok: false, reason: "malformed" });
  });

  it("malformed for total garbage (no dot structure)", async () => {
    const verifier = buildVerifier();
    const res = await verifier.verify("totally-not-a-token");
    expect(res).toEqual({ ok: false, reason: "malformed" });
  });

  it("expired when a validly-signed token carries NO exp claim (requiredClaims)", async () => {
    // A token signed by the trusted key but WITHOUT an exp claim. jose only
    // enforces exp when present, so requiredClaims: ["exp"] is what rejects this
    // — without it the token would be treated as non-expiring.
    const verifier = buildVerifier();
    const token = await new SignJWT({ email: "a@b.com", email_verified: true })
      .setProtectedHeader({ alg: "RS256", kid: KID })
      .setSubject("google-sub-1234567890")
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setIssuedAt(NOW_SEC - 60)
      // deliberately no setExpirationTime()
      .sign(privateKey);
    const res = await verifier.verify(token);
    expect(res).toEqual({ ok: false, reason: "expired" });
  });

  it("malformed when a validly-signed token has NO sub claim", async () => {
    // A token signed by the trusted key, passing iss/aud/exp/email_verified,
    // but with no sub. The verifier must reject rather than project
    // "google:undefined".
    const verifier = buildVerifier();
    const token = await new SignJWT({ email: "a@b.com", email_verified: true })
      .setProtectedHeader({ alg: "RS256", kid: KID })
      // deliberately no setSubject()
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setIssuedAt(NOW_SEC - 60)
      .setExpirationTime(NOW_SEC + 3600)
      .sign(privateKey);
    const res = await verifier.verify(token);
    expect(res).toEqual({ ok: false, reason: "malformed" });
  });
});
