/**
 * Core result types for @bugbubug/auth-kit. These are the frozen output shapes
 * the two verification methods produce. Frozen baseline: etc/auth-kit.api.md.
 *
 * The SDK ONLY verifies control of an identifier — it never decides
 * users/sessions/register-vs-login, never sets cookies, never stores user rows.
 */
/**
 * Thrown ONLY for programmer/configuration faults the caller cannot recover from
 * at runtime (e.g. an OtpStore that rejects writes, a JwksSource that throws, an
 * empty allowedAudiences). Expected auth outcomes are NEVER thrown — they come
 * back in the discriminated unions above. `code` is a stable machine string.
 */
export class AuthKitError extends Error {
    code;
    constructor(code, message, 
    /** Optional underlying cause (network error, adapter exception). */
    options) {
        super(message, options);
        this.name = "AuthKitError";
        this.code = code;
        // Restore prototype chain for instanceof across down-leveled targets.
        Object.setPrototypeOf(this, AuthKitError.prototype);
    }
}
//# sourceMappingURL=types.js.map