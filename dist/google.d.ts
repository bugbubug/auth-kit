/**
 * Google id_token verifier — a thin PRESET over the generic OIDC engine
 * (./oidc): validateGoogleConfig keeps the Google-specific defaulting (the two
 * Google issuers) and its exact error messages, then delegates to
 * createOidcVerifier with subjectPrefix "google" (RS256 allowlist,
 * email_verified required — the engine's defaults ARE the Google policy).
 *
 * The verification pipeline itself — structural JWT parse, local-JWKS signature
 * verification via the injected JwksSource port (never
 * jose.createRemoteJWKSet), iss/aud/exp against the injected Clock, the
 * email_verified/email/sub claim policy, and the VerifiedIdentity projection
 * (providerSubject `google:<sub>`, normalized email, optional displayName from
 * `name`) — lives in ./oidc and behaves byte-for-byte as it did here.
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