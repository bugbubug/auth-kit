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
import { validateGoogleConfig } from "./config.js";
import { createOidcVerifier } from "./oidc.js";
export function createGoogleVerifier(deps, config) {
    // Validates + applies issuer defaults; throws AuthKitError("config_invalid")
    // on an empty/invalid allowedAudiences (a wildcard audience is never allowed)
    // — with the Google-specific error messages, BEFORE the generic engine sees
    // the config (a Google-validated config always passes the OIDC validator).
    const cfg = validateGoogleConfig(config);
    return createOidcVerifier(deps, {
        allowedIssuers: cfg.allowedIssuers,
        allowedAudiences: cfg.allowedAudiences,
        subjectPrefix: "google",
        // algorithms ["RS256"], requireEmailVerified true, and displayNameClaim
        // "name" are the engine defaults — exactly the historical Google behavior.
    });
}
//# sourceMappingURL=google.js.map