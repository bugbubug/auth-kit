/**
 * Email OTP engine — the deterministic start/verify flow over the injected
 * OtpStore + EmailSender ports. Pure, framework/runtime-agnostic: WebCrypto only
 * (via ./crypto), no Hono / Workers / Node imports.
 *
 * Flow ownership (hexagonal):
 *   • The CORE owns key derivation, throttle, code hashing, expiry/attempt
 *     bookkeeping, and the single-use consume. It NEVER stores plaintext codes
 *     (only sha-256 hex) and NEVER builds keys outside `otpKey`.
 *   • The CONSUMER injects persistence (OtpStore) and delivery (EmailSender).
 *
 * Result model: every EXPECTED outcome is a discriminated-union return value
 * (StartOtpResult / VerifyOtpResult). Only ADAPTER faults — a store that rejects
 * a read/write/increment, or a sender that throws — surface as AuthKitError
 * ("store_failure" / "email_send_failure"). A throttle or a wrong code is a
 * normal outcome, never an exception.
 */
import type { EmailOtpConfig } from "./config.js";
import type { Clock, CodeGenerator, EmailSender, OtpStore } from "./ports.js";
import type { StartOtpResult, VerifyOtpResult } from "./types.js";
/** Dependency bundle for the Email OTP engine (frozen contract section 5). */
export interface EmailOtpDeps {
    store: OtpStore;
    sender: EmailSender;
    /** Defaults to the WebCrypto-backed `defaultCodeGenerator` if omitted. */
    codeGen?: CodeGenerator;
    /** Defaults to the `Date.now()`-backed `systemClock` if omitted. */
    clock?: Clock;
}
/** The two-method service the factory produces (frozen contract section 5). */
export interface EmailOtpService {
    /**
     * Begin/refresh an OTP for `email`. Normalizes the address, enforces the
     * resend throttle against the existing record's `issuedAt`, otherwise
     * generates+hashes+stores a fresh code and sends it. Returns "sent" with the
     * expiry, or "throttled" with `retryAfter` + the existing code's expiry.
     * Throws AuthKitError only on a store/sender fault.
     */
    startOtp(email: string): Promise<StartOtpResult>;
    /**
     * Verify `code` for `email`. On success returns the VerifiedIdentity and
     * consumes the record (single-use). On failure returns a typed reason; a
     * mismatch consumes an attempt and locks at maxAttempts. Never throws for an
     * expected failure — only on a store fault.
     */
    verifyOtp(email: string, code: string): Promise<VerifyOtpResult>;
}
export declare function createEmailOtpService(deps: EmailOtpDeps, config?: EmailOtpConfig): EmailOtpService;
//# sourceMappingURL=email-otp.d.ts.map