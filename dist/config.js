/**
 * CONFIG types + their applied defaults and validators. Frozen baseline:
 * etc/auth-kit.api.md (the config shapes); the helpers below are the deterministic
 * default-application / validation logic the engine factories call.
 */
import { AuthKitError } from "./types.js";
/** The applied (no-undefined) Email OTP config, exported for callers that want the defaults. */
export const EMAIL_OTP_DEFAULTS = {
    length: 6,
    ttlSeconds: 600,
    resendThrottleSeconds: 60,
    maxAttempts: 5,
};
/**
 * Merge a partial EmailOtpConfig over EMAIL_OTP_DEFAULTS into a fully-applied
 * (no-undefined) config, validating every effective value. A non-positive (or
 * non-integer, non-finite) number for any field is a programmer/config fault and
 * throws AuthKitError("config_invalid") at construction — never a silent fallback.
 */
export function applyEmailDefaults(config) {
    const applied = {
        length: config?.length ?? EMAIL_OTP_DEFAULTS.length,
        ttlSeconds: config?.ttlSeconds ?? EMAIL_OTP_DEFAULTS.ttlSeconds,
        resendThrottleSeconds: config?.resendThrottleSeconds ?? EMAIL_OTP_DEFAULTS.resendThrottleSeconds,
        maxAttempts: config?.maxAttempts ?? EMAIL_OTP_DEFAULTS.maxAttempts,
    };
    for (const [key, value] of Object.entries(applied)) {
        if (!Number.isInteger(value) || value <= 0) {
            throw new AuthKitError("config_invalid", `EmailOtpConfig.${key} must be a positive integer, got ${String(value)}`);
        }
    }
    return applied;
}
export const GOOGLE_DEFAULT_ISSUERS = [
    "https://accounts.google.com",
    "accounts.google.com",
];
/**
 * Validate + apply defaults for a GoogleVerifierConfig. Throws
 * AuthKitError("config_invalid") when:
 *   • allowedAudiences is missing, not an array, empty, or contains a
 *     non-string / blank entry (a wildcard audience is never allowed); or
 *   • allowedIssuers is provided but empty / contains a blank entry.
 * Returns a fully-applied config with GOOGLE_DEFAULT_ISSUERS substituted when
 * allowedIssuers is omitted.
 */
export function validateGoogleConfig(config) {
    const audiences = config?.allowedAudiences;
    if (!Array.isArray(audiences) || audiences.length === 0) {
        throw new AuthKitError("config_invalid", "GoogleVerifierConfig.allowedAudiences must be a non-empty array (a wildcard audience is never allowed)");
    }
    for (const aud of audiences) {
        if (typeof aud !== "string" || aud.trim() === "") {
            throw new AuthKitError("config_invalid", "GoogleVerifierConfig.allowedAudiences entries must be non-empty strings");
        }
    }
    let issuers;
    if (config.allowedIssuers === undefined) {
        issuers = [...GOOGLE_DEFAULT_ISSUERS];
    }
    else {
        if (!Array.isArray(config.allowedIssuers) ||
            config.allowedIssuers.length === 0) {
            throw new AuthKitError("config_invalid", "GoogleVerifierConfig.allowedIssuers, when provided, must be a non-empty array");
        }
        for (const iss of config.allowedIssuers) {
            if (typeof iss !== "string" || iss.trim() === "") {
                throw new AuthKitError("config_invalid", "GoogleVerifierConfig.allowedIssuers entries must be non-empty strings");
            }
        }
        issuers = [...config.allowedIssuers];
    }
    return { allowedAudiences: [...audiences], allowedIssuers: issuers };
}
//# sourceMappingURL=config.js.map