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
import type { GoogleVerifierConfig } from "./config.js";
import type { Clock, JwksSource } from "./ports.js";
import type { VerifyGoogleResult } from "./types.js";
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
export declare function createGoogleVerifier(deps: GoogleVerifierDeps, config: GoogleVerifierConfig): GoogleVerifier;
//# sourceMappingURL=google.d.ts.map