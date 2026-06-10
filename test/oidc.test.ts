/**
 * Generic OIDC verifier tests — fully deterministic, ZERO egress. Same harness
 * pattern as google.test.ts (jose generateKeyPair + StaticJwksSource + fixed
 * Clock), but against a CUSTOM issuer/audience/subjectPrefix to prove the
 * engine is provider-agnostic (the Google preset's behavior is pinned by
 * google.test.ts, which runs UNCHANGED over the same engine).
 *
 * Covers: custom-provider happy path (-> `<prefix>:<sub>` providerSubject +
 * provider discriminant), untrusted_issuer, untrusted_audience, expired,
 * requireEmailVerified:false (accepts an unverified email and surfaces
 * emailVerified:false; email itself stays REQUIRED), and the construction-time
 * config_invalid faults (empty issuers/audiences, blank subjectPrefix, empty
 * algorithms).
 */

import { describe, expect, it, beforeAll } from "bun:test";
import {
  generateKeyPair,
  exportJWK,
  SignJWT,
  type JWK,
  type CryptoKey as JoseCryptoKey,
} from "jose";

import { createOidcVerifier } from "../src/oidc.js";
import { StaticJwksSource } from "../src/adapters/static-jwks.js";
import type { OidcVerifierConfig } from "../src/config.js";
import { AuthKitError } from "../src/types.js";
import type { Clock, Jwk } from "../src/ports.js";

// ── Fixtures (a NON-Google provider to prove genericity) ────────────────────

const KID = "oidc-test-kid-1";
const ISSUER = "https://id.example-provider.com";
const AUDIENCE = "example-client-id";
const PREFIX = "exampleidp";

// A fixed point in (real-ish) time, in epoch SECONDS, for deterministic exp.
const NOW_SEC = 1_700_000_000;

/** Fixed Clock pinned to NOW_SEC (the source feeds clock.now() ms to jose). */
const fixedClock: Clock = { now: () => NOW_SEC * 1000 };

let privateKey: JoseCryptoKey;
let publicJwk: Jwk;

beforeAll(async () => {
  const pair = await generateKeyPair("RS256", { extractable: true });
  privateKey = pair.privateKey;
  const jwk: JWK = await exportJWK(pair.publicKey);
  jwk.kid = KID;
  jwk.alg = "RS256";
  jwk.use = "sig";
  publicJwk = jwk as Jwk;
});

/** Build a verifier over the trusted JWKS + fixed clock. */
function buildVerifier(overrides?: Partial<OidcVerifierConfig>) {
  const jwks = new StaticJwksSource([publicJwk]);
  const cfg: OidcVerifierConfig = {
    allowedIssuers: [ISSUER],
    allowedAudiences: [AUDIENCE],
    subjectPrefix: PREFIX,
    ...overrides,
  };
  return createOidcVerifier({ jwks, clock: fixedClock }, cfg);
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

/** Forge an id_token signed by the trusted private key. */
async function signToken(claims: ClaimOverrides = {}): Promise<string> {
  const payload: Record<string, unknown> = {};
  if (claims.email !== undefined) payload.email = claims.email;
  if ("email_verified" in claims) payload.email_verified = claims.email_verified;
  else payload.email_verified = true;
  if (claims.name !== undefined) payload.name = claims.name;

  const exp = claims.exp ?? NOW_SEC + 3600;
  const iat = claims.iat ?? NOW_SEC - 60;

  return new SignJWT(payload)
    .setProtectedHeader({ alg: "RS256", kid: KID })
    .setSubject(claims.sub ?? "idp-sub-0001")
    .setIssuer(claims.iss ?? ISSUER)
    .setAudience(claims.aud ?? AUDIENCE)
    .setIssuedAt(iat)
    .setExpirationTime(exp)
    .sign(privateKey);
}

// ── Happy path with a custom provider ────────────────────────────────────────

describe("OIDC verifier — custom provider happy path", () => {
  it("verifies a custom-issuer token -> <prefix>:<sub>, provider, normalized email, displayName", async () => {
    const verifier = buildVerifier();
    const token = await signToken({
      sub: "idp-sub-0001",
      email: "  Person@Example.COM  ",
      email_verified: true,
      name: "Real Person",
    });

    const res = await verifier.verify(token);

    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error("expected ok");
    // providerSubject is `${subjectPrefix}:${sub}`, NEVER the email.
    expect(res.identity.providerSubject).toBe(`${PREFIX}:idp-sub-0001`);
    // The provider discriminant matches the configured subjectPrefix.
    expect(res.identity.provider).toBe(PREFIX);
    // email is normalized (trim + lowercase).
    expect(res.identity.email).toBe("person@example.com");
    expect(res.identity.emailVerified).toBe(true);
    expect(res.identity.displayName).toBe("Real Person");
  });
});

// ── Failure reasons against the custom provider config ──────────────────────

describe("OIDC verifier — failure reasons", () => {
  it("untrusted_issuer when iss is not in allowedIssuers", async () => {
    const verifier = buildVerifier();
    const token = await signToken({
      iss: "https://evil.example.com",
      email: "a@b.com",
    });
    const res = await verifier.verify(token);
    expect(res).toEqual({ ok: false, reason: "untrusted_issuer" });
  });

  it("untrusted_audience when aud is not in allowedAudiences", async () => {
    const verifier = buildVerifier();
    const token = await signToken({ aud: "some-other-aud", email: "a@b.com" });
    const res = await verifier.verify(token);
    expect(res).toEqual({ ok: false, reason: "untrusted_audience" });
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
});

// ── email_verified policy ────────────────────────────────────────────────────

describe("OIDC verifier — requireEmailVerified policy", () => {
  it("default policy rejects an email_verified:false token (email_unverified)", async () => {
    const verifier = buildVerifier();
    const token = await signToken({ email: "a@b.com", email_verified: false });
    const res = await verifier.verify(token);
    expect(res).toEqual({ ok: false, reason: "email_unverified" });
  });

  it("requireEmailVerified:false accepts email_verified:false and surfaces emailVerified:false", async () => {
    const verifier = buildVerifier({ requireEmailVerified: false });
    const token = await signToken({ email: "a@b.com", email_verified: false });
    const res = await verifier.verify(token);
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error("expected ok");
    expect(res.identity.emailVerified).toBe(false);
    expect(res.identity.providerSubject).toBe(`${PREFIX}:idp-sub-0001`);
  });

  it("requireEmailVerified:false surfaces emailVerified:true for a 'true' string claim", async () => {
    const verifier = buildVerifier({ requireEmailVerified: false });
    const token = await signToken({ email: "a@b.com", email_verified: "true" });
    const res = await verifier.verify(token);
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error("expected ok");
    expect(res.identity.emailVerified).toBe(true);
  });

  it("requireEmailVerified:false still REQUIRES an email claim (missing_email)", async () => {
    const verifier = buildVerifier({ requireEmailVerified: false });
    const token = await signToken({ email: undefined, email_verified: false });
    const res = await verifier.verify(token);
    expect(res).toEqual({ ok: false, reason: "missing_email" });
  });
});

// ── Construction-time config faults ──────────────────────────────────────────

describe("OIDC verifier — config validation (AuthKitError config_invalid)", () => {
  function buildWith(cfg: OidcVerifierConfig) {
    const jwks = new StaticJwksSource([publicJwk]);
    return () => createOidcVerifier({ jwks, clock: fixedClock }, cfg);
  }

  function expectConfigInvalid(build: () => unknown, messagePart: string) {
    let caught: unknown;
    try {
      build();
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(AuthKitError);
    expect((caught as AuthKitError).code).toBe("config_invalid");
    expect((caught as AuthKitError).message).toContain(messagePart);
  }

  it("throws for empty allowedIssuers (generic OIDC has no default issuers)", () => {
    expectConfigInvalid(
      buildWith({
        allowedIssuers: [],
        allowedAudiences: [AUDIENCE],
        subjectPrefix: PREFIX,
      }),
      "allowedIssuers",
    );
  });

  it("throws for empty allowedAudiences", () => {
    expectConfigInvalid(
      buildWith({
        allowedIssuers: [ISSUER],
        allowedAudiences: [],
        subjectPrefix: PREFIX,
      }),
      "allowedAudiences",
    );
  });

  it("throws for a blank subjectPrefix", () => {
    expectConfigInvalid(
      buildWith({
        allowedIssuers: [ISSUER],
        allowedAudiences: [AUDIENCE],
        subjectPrefix: "   ",
      }),
      "subjectPrefix",
    );
  });

  it("throws for an empty provided algorithms allowlist", () => {
    expectConfigInvalid(
      buildWith({
        allowedIssuers: [ISSUER],
        allowedAudiences: [AUDIENCE],
        subjectPrefix: PREFIX,
        algorithms: [],
      }),
      "algorithms",
    );
  });

  it("throws for a blank allowedIssuers entry", () => {
    expectConfigInvalid(
      buildWith({
        allowedIssuers: ["  "],
        allowedAudiences: [AUDIENCE],
        subjectPrefix: PREFIX,
      }),
      "allowedIssuers entries",
    );
  });
});
