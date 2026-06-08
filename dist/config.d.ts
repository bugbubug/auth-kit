/**
 * CONFIG types + their applied defaults and validators. Frozen baseline:
 * etc/auth-kit.api.md (the config shapes); the helpers below are the deterministic
 * default-application / validation logic the engine factories call.
 */
/** Email OTP tunables. All optional; defaults match the locked spec. */
export interface EmailOtpConfig {
    /** Digits in the code. Default 6. */
    length?: number;
    /** Code lifetime in seconds. Default 600 (10 minutes). */
    ttlSeconds?: number;
    /** Minimum seconds between sends to the same email. Default 60. */
    resendThrottleSeconds?: number;
    /** Verify attempts allowed per active code before lock. Default 5. */
    maxAttempts?: number;
}
/** The applied (no-undefined) Email OTP config, exported for callers that want the defaults. */
export declare const EMAIL_OTP_DEFAULTS: Required<EmailOtpConfig>;
/**
 * Merge a partial EmailOtpConfig over EMAIL_OTP_DEFAULTS into a fully-applied
 * (no-undefined) config, validating every effective value. A non-positive (or
 * non-integer, non-finite) number for any field is a programmer/config fault and
 * throws AuthKitError("config_invalid") at construction — never a silent fallback.
 */
export declare function applyEmailDefaults(config?: EmailOtpConfig): Required<EmailOtpConfig>;
export interface GoogleVerifierConfig {
    /**
     * The OAuth client id(s) a valid id_token's `aud` must be one of. REQUIRED and
     * non-empty — an empty list throws AuthKitError("config_invalid") at
     * construction (a wildcard audience is never allowed).
     */
    allowedAudiences: string[];
    /**
     * Accepted `iss` values. Defaults to Google's two issuers:
     * ["https://accounts.google.com", "accounts.google.com"].
     */
    allowedIssuers?: string[];
}
export declare const GOOGLE_DEFAULT_ISSUERS: readonly string[];
/** The applied (no-undefined) Google verifier config. */
export interface AppliedGoogleConfig {
    allowedAudiences: string[];
    allowedIssuers: string[];
}
/**
 * Validate + apply defaults for a GoogleVerifierConfig. Throws
 * AuthKitError("config_invalid") when:
 *   • allowedAudiences is missing, not an array, empty, or contains a
 *     non-string / blank entry (a wildcard audience is never allowed); or
 *   • allowedIssuers is provided but empty / contains a blank entry.
 * Returns a fully-applied config with GOOGLE_DEFAULT_ISSUERS substituted when
 * allowedIssuers is omitted.
 */
export declare function validateGoogleConfig(config: GoogleVerifierConfig): AppliedGoogleConfig;
//# sourceMappingURL=config.d.ts.map