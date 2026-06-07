/**
 * Google id_token verifier — verifies a GIS-issued id_token against Google's
 * JWKS with `jose`, then enforces iss/aud/exp + email_verified, and projects the
 * VerifiedIdentity (providerSubject `google:<sub>`, normalized email, optional
 * displayName from `name`).
 *
 * Hexagonal: the CORE owns the structural parse, signature verification, claim
 * checks, and identity projection. The CONSUMER injects a JwksSource (real fetch
 * adapter in production; a StaticJwksSource in tests — zero egress) and a Clock.
 *
 * Egress discipline: this file performs NO network I/O. Signature verification
 * runs against a LOCAL JWK set built from `jwks.getKeys()` via
 * `jose.createLocalJWKSet`. `jose.createRemoteJWKSet` is NEVER used here — that
 * would fetch behind the core's back and break the injected-source contract +
 * zero-egress tests. Any real fetch lives entirely inside the injected adapter.
 *
 * Result model: every EXPECTED verification outcome is a typed
 * GoogleFailureReason in the VerifyGoogleResult union — never thrown. Only a
 * JwksSource adapter fault surfaces as AuthKitError("jwks_failure"); an empty
 * allowedAudiences is a config fault thrown at construction.
 */

import { createLocalJWKSet, errors as joseErrors, jwtVerify } from "jose";
import type { JWTPayload, JSONWebKeySet } from "jose";

import type { GoogleVerifierConfig } from "./config.js";
import { validateGoogleConfig } from "./config.js";
import type { Clock, JwksSource } from "./ports.js";
import type { GoogleFailureReason, VerifyGoogleResult } from "./types.js";
import { AuthKitError } from "./types.js";
import { normalizeEmail, systemClock } from "./util.js";

/** Dependency bundle for the Google verifier (frozen contract section 5). */
export interface GoogleVerifierDeps {
  jwks: JwksSource;
  /** Defaults to the `Date.now()`-backed `systemClock` if omitted. */
  clock?: Clock;
}

/** The single-method verifier the factory produces (frozen contract section 5). */
export interface GoogleVerifier {
  /**
   * Verify a GIS-issued id_token: structurally parse, verify the signature
   * against the JWKS, check iss ∈ allowedIssuers / aud ∈ allowedAudiences /
   * exp per the injected Clock, then require email_verified and a usable email.
   * Returns the VerifiedIdentity or a typed reason. Never throws for an expected
   * verification failure; a JwksSource fault throws AuthKitError("jwks_failure").
   */
  verify(idToken: string): Promise<VerifyGoogleResult>;
}

export function createGoogleVerifier(
  deps: GoogleVerifierDeps,
  config: GoogleVerifierConfig,
): GoogleVerifier {
  const { jwks } = deps;
  const clock = deps.clock ?? systemClock;
  // Validates + applies issuer defaults; throws AuthKitError("config_invalid")
  // on an empty/invalid allowedAudiences (a wildcard audience is never allowed).
  const cfg = validateGoogleConfig(config);

  async function verify(idToken: string): Promise<VerifyGoogleResult> {
    // 1. Structural parse — three dot-separated base64url segments and a
    //    decodable header carrying alg/kid. A malformed token never reaches
    //    `jose` (and a bad header would surface as a parse failure anyway).
    if (!isStructurallyValidJwt(idToken)) {
      return fail("malformed");
    }

    // 2. Build a LOCAL JWK set from the injected source. The getKeys() call is
    //    the ONLY place an adapter fault can occur; map it to jwks_failure.
    let keySet: { keys: unknown[] };
    try {
      keySet = await jwks.getKeys();
    } catch (cause) {
      throw new AuthKitError(
        "jwks_failure",
        "JwksSource.getKeys failed while verifying a Google id_token",
        { cause },
      );
    }
    const localJwks = createLocalJWKSet(keySet as JSONWebKeySet);

    // 3. Verify signature + iss/aud/exp via jose against the LOCAL set. The
    //    Clock drives expiry: `currentDate` defaults to new Date() in jose, so
    //    we pin it to the injected clock's millis for deterministic exp checks.
    //
    //    `algorithms: ["RS256"]` is an EXPLICIT allowlist: Google id_tokens are
    //    always RS256, and pinning it makes the alg-confusion guarantee a
    //    property THIS file asserts rather than relying on jose internals
    //    (createLocalJWKSet's getKtyFromAlg / checkKeyType) to reject `none`,
    //    HS256-with-an-RSA-key, or any future EC/OKP key that drifts into the set.
    //
    //    `requiredClaims: ["exp"]` makes a missing-`exp` token fail closed: jose
    //    only enforces `exp` WHEN PRESENT, so without this an otherwise-valid
    //    token lacking `exp` would be treated as non-expiring. Genuine Google
    //    id_tokens always carry `exp`, so this rejects nothing legitimate.
    let payload: JWTPayload;
    try {
      const result = await jwtVerify(idToken, localJwks, {
        algorithms: ["RS256"],
        issuer: cfg.allowedIssuers,
        audience: cfg.allowedAudiences,
        currentDate: new Date(clock.now()),
        requiredClaims: ["exp"],
      });
      payload = result.payload;
    } catch (err) {
      return fail(mapJoseError(err));
    }

    // 4. Claim policy beyond signature/iss/aud/exp: Google requires
    //    email_verified to be true (boolean true or the string "true") and a
    //    usable email claim. `sub` is NOT required by jose unless the `subject`
    //    option is passed (it isn't), so we validate it explicitly below.
    const emailVerified =
      payload.email_verified === true || payload.email_verified === "true";
    if (!emailVerified) {
      return fail("email_unverified");
    }

    const rawEmail = payload.email;
    if (typeof rawEmail !== "string" || rawEmail.trim() === "") {
      return fail("missing_email");
    }

    // `sub` must be a non-empty string: it IS the stable identity key. A token
    // signed by a real Google key but missing `sub` would otherwise project to
    // the colliding "google:undefined" — reject it as malformed instead.
    if (typeof payload.sub !== "string" || payload.sub.trim() === "") {
      return fail("malformed");
    }

    // 5. Project the VerifiedIdentity. providerSubject is the stable `sub`
    //    (NEVER the email), prefixed `google:`; email is normalized; name -> displayName.
    return {
      ok: true,
      identity: {
        providerSubject: "google:" + payload.sub,
        email: normalizeEmail(rawEmail),
        emailVerified: true,
        displayName:
          payload.name !== undefined && payload.name !== null
            ? String(payload.name)
            : undefined,
      },
    };
  }

  return { verify };
}

// ───────────────────────────────────────────────────────────────────────────
// Helpers.
// ───────────────────────────────────────────────────────────────────────────

function fail(reason: GoogleFailureReason): VerifyGoogleResult {
  return { ok: false, reason };
}

/**
 * Cheap structural pre-check before handing the token to `jose`: exactly three
 * non-empty base64url segments, and a header that base64url-decodes to JSON
 * carrying an `alg`. We do NOT trust anything here — it only lets us return the
 * `malformed` reason for garbage that isn't a parseable JWT shape.
 */
function isStructurallyValidJwt(token: string): boolean {
  if (typeof token !== "string") return false;
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  if (parts[0] === "" || parts[1] === "" || parts[2] === "") return false;
  try {
    const header = decodeBase64UrlJson(parts[0]);
    if (typeof header !== "object" || header === null) return false;
    const alg = (header as Record<string, unknown>).alg;
    if (typeof alg !== "string" || alg === "") return false;
    return true;
  } catch {
    return false;
  }
}

/** Decode a base64url segment to a parsed JSON value. Throws on bad input. */
function decodeBase64UrlJson(segment: string): unknown {
  const base64 = segment.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  const json = new TextDecoder().decode(bytes);
  return JSON.parse(json);
}

/**
 * Map a thrown `jose` error to the typed GoogleFailureReason. Prefer the stable
 * `.code` strings (resilient to message changes / bundling):
 *   • ERR_JWT_EXPIRED                       -> expired
 *   • ERR_JWS_SIGNATURE_VERIFICATION_FAILED -> bad_signature
 *   • ERR_JWT_CLAIM_VALIDATION_FAILED       -> iss/aud claim => untrusted_*,
 *                                              nbf/iat time claim => expired
 *   • everything else (JWSInvalid / JWTInvalid / JWKS no-match / alg not allowed /
 *     decode errors) -> malformed
 */
function mapJoseError(err: unknown): GoogleFailureReason {
  if (err instanceof joseErrors.JWTExpired) {
    return "expired";
  }
  if (err instanceof joseErrors.JWSSignatureVerificationFailed) {
    return "bad_signature";
  }
  // An alg outside the ["RS256"] allowlist (or a `none` alg) is an explicit
  // policy rejection, not a structural one. Map it to bad_signature so the
  // caller sees "this token's signature is not acceptable" rather than
  // "garbage" — and so the allowlist's intent is documented here.
  if (err instanceof joseErrors.JOSEAlgNotAllowed) {
    return "bad_signature";
  }
  if (err instanceof joseErrors.JWTClaimValidationFailed) {
    const claim = err.claim;
    if (claim === "iss") return "untrusted_issuer";
    if (claim === "aud") return "untrusted_audience";
    // nbf / iat / exp (and any other time-bound claim) read as invalid temporal
    // claims, which fold into the "expired" reason. A required-but-absent `exp`
    // (we pass requiredClaims: ["exp"]) surfaces here as claim "exp", reason
    // "missing" — a token without an expiry must NOT be treated as eternal.
    if (claim === "nbf" || claim === "iat" || claim === "exp") return "expired";
    // A required-but-absent iss/aud surfaces here too; treat as untrusted.
    if (err.reason === "missing") {
      if (err.message.includes('"iss"')) return "untrusted_issuer";
      if (err.message.includes('"aud"')) return "untrusted_audience";
    }
    return "malformed";
  }
  // JWSInvalid, JWTInvalid, JWKSNoMatchingKey, JWKSInvalid, base64/JSON decode
  // faults, and anything unrecognized: not a structurally verifiable token
  // against our keys.
  return "malformed";
}
