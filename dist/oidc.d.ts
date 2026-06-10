/**
 * Generic OIDC id_token verifier — the engine the provider presets (Google
 * today; Apple/Microsoft tomorrow) are thin configs over. Verifies an id_token
 * against the injected JWKS with `jose`, enforces iss/aud/exp + the
 * email_verified policy, and projects the VerifiedIdentity (providerSubject
 * `<subjectPrefix>:<sub>`, normalized email, optional displayName from the
 * configured claim).
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
 * OidcFailureReason in the VerifyOidcResult union — never thrown. Only a
 * JwksSource adapter fault surfaces as AuthKitError("jwks_failure"); an
 * invalid config (empty issuers/audiences, blank subjectPrefix, …) is a config
 * fault thrown at construction.
 */
import type { OidcVerifierConfig } from "./config.js";
import type { Clock, JwksSource } from "./ports.js";
import type { VerifyOidcResult } from "./types.js";
/** Dependency bundle for the generic OIDC verifier (same shape as GoogleVerifierDeps). */
export interface OidcVerifierDeps {
    jwks: JwksSource;
    /** Defaults to the `Date.now()`-backed `systemClock` if omitted. */
    clock?: Clock;
}
/** The single-method verifier the factory produces. */
export interface OidcVerifier {
    /**
     * Verify an OIDC id_token: structurally parse, verify the signature against
     * the JWKS, check iss ∈ allowedIssuers / aud ∈ allowedAudiences / exp per the
     * injected Clock, then apply the email_verified policy and require a usable
     * email + sub. Returns the VerifiedIdentity or a typed reason. Never throws
     * for an expected verification failure; a JwksSource fault throws
     * AuthKitError("jwks_failure").
     */
    verify(idToken: string): Promise<VerifyOidcResult>;
}
export declare function createOidcVerifier(deps: OidcVerifierDeps, config: OidcVerifierConfig): OidcVerifier;
//# sourceMappingURL=oidc.d.ts.map