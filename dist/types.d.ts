/**
 * Core result types for @bugbubug/auth-kit. These are the frozen output shapes
 * the two verification methods produce. Frozen baseline: etc/auth-kit.api.md.
 *
 * The SDK ONLY verifies control of an identifier — it never decides
 * users/sessions/register-vs-login, never sets cookies, never stores user rows.
 */
/**
 * The verified read of the principal behind a proven identifier. This is the
 * ONLY success payload either method returns.
 *
 * emo glue (near-zero) — given `id: VerifiedIdentity`, emo builds its
 * IdentityResult as:
 *   { providerSubject: id.providerSubject,
 *     profile: { email: id.email, displayName: id.displayName } }
 */
export interface VerifiedIdentity {
    /**
     * The provider's stable, opaque subject for this principal. Maps directly to
     * emo's `IdentityResult.providerSubject` and is the key in emo's
     * (productId, provider, providerSubject) unique index.
     *   • Email OTP: `email:<normalizedEmail>` (control of the address IS the id).
     *   • Google:    `google:<sub>` (Google's stable `sub` claim, NEVER the email).
     * The `<provider>:` prefix is part of the frozen format so two methods that
     * resolve the same human never collide on a bare value.
     */
    providerSubject: string;
    /**
     * The verification method/provider that produced this identity, e.g. "email"
     * or "google" (matches the providerSubject prefix). Optional in the type for
     * frozen-contract compatibility; always populated by the engines from v1.2.
     */
    provider?: string;
    /**
     * The address, ALWAYS normalized: trimmed + lowercased. For Email OTP this is
     * the verified address; for Google it is the `email` claim (only present when
     * emailVerified is true — see below).
     */
    email: string;
    /**
     * Whether the email is provider-verified.
     *   • Email OTP: always `true` (control of the inbox was just proven).
     *   • Google: mirrors the `email_verified` claim; the verifier REQUIRES it to
     *     be true to succeed, so in practice this is always `true` on success. It
     *     is surfaced explicitly so emo's account-linking policy reads it directly
     *     rather than re-deriving it.
     */
    emailVerified: boolean;
    /** Optional human-friendly name (Google `name` claim; absent for Email OTP). */
    displayName?: string;
}
/** Why an Email OTP start could not proceed normally. */
export type StartOtpResult = {
    status: "sent";
    /** Unix epoch SECONDS at which the active code expires. */
    expiresAt: number;
} | {
    status: "throttled";
    /** Seconds the caller must wait before another send is allowed (resend throttle). */
    retryAfter: number;
    /** Unix epoch SECONDS at which the EXISTING (still-valid) code expires. */
    expiresAt: number;
};
/** Why an Email OTP verify failed (expected, caller-recoverable). */
export type OtpFailureReason = "expired" | "mismatch" | "locked" | "not_found";
export type VerifyOtpResult = {
    ok: true;
    identity: VerifiedIdentity;
} | {
    ok: false;
    reason: OtpFailureReason;
};
/** Why a Google id_token verification failed (expected). */
export type GoogleFailureReason = "malformed" | "bad_signature" | "untrusted_issuer" | "untrusted_audience" | "expired" | "email_unverified" | "missing_email";
export type VerifyGoogleResult = {
    ok: true;
    identity: VerifiedIdentity;
} | {
    ok: false;
    reason: GoogleFailureReason;
};
/**
 * Why a generic OIDC id_token verification failed (expected). The generic OIDC
 * pipeline (createOidcVerifier) is the engine the Google verifier is a preset
 * of, so it produces the exact same reason set — this alias names that fact
 * additively without retyping the frozen GoogleFailureReason.
 */
export type OidcFailureReason = GoogleFailureReason;
/**
 * Result of a generic OIDC id_token verification. Identical to the frozen
 * VerifyGoogleResult (the Google verifier is a preset of the OIDC pipeline);
 * the alias exists so OIDC-generic call sites don't have to name a
 * Google-specific type.
 */
export type VerifyOidcResult = VerifyGoogleResult;
/**
 * Thrown ONLY for programmer/configuration faults the caller cannot recover from
 * at runtime (e.g. an OtpStore that rejects writes, a JwksSource that throws, an
 * empty allowedAudiences). Expected auth outcomes are NEVER thrown — they come
 * back in the discriminated unions above. `code` is a stable machine string.
 */
export declare class AuthKitError extends Error {
    readonly code: "store_failure" | "jwks_failure" | "email_send_failure" | "config_invalid";
    constructor(code: AuthKitError["code"], message: string, 
    /** Optional underlying cause (network error, adapter exception). */
    options?: {
        cause?: unknown;
    });
}
//# sourceMappingURL=types.d.ts.map