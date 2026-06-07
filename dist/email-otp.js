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
import { applyEmailDefaults } from "./config.js";
import { AuthKitError } from "./types.js";
import { constantTimeEqualHex, defaultCodeGenerator, sha256Hex } from "./crypto.js";
import { normalizeEmail, otpKey, systemClock } from "./util.js";
/**
 * A fixed 64-char (sha-256-width) lowercase-hex dummy, compared against on the
 * not-found path so it does the same hash+constant-time-compare work a wrong
 * code does — equalizing timing so "no record" is not measurably faster than
 * "wrong code". The value is irrelevant (the compare's result is discarded); it
 * only must be the same width as a real sha-256 hex so the compare loop runs
 * the same number of iterations.
 */
const DUMMY_HASH = "0".repeat(64);
export function createEmailOtpService(deps, config) {
    const { store, sender } = deps;
    const codeGen = deps.codeGen ?? defaultCodeGenerator;
    const clock = deps.clock ?? systemClock;
    // Validates + applies defaults; throws AuthKitError("config_invalid") on a
    // non-positive/non-integer tunable at construction.
    const cfg = applyEmailDefaults(config);
    const nowSec = () => Math.floor(clock.now() / 1000);
    async function startOtp(email) {
        const normalized = normalizeEmail(email);
        const key = otpKey(normalized);
        const now = nowSec();
        // Read any active record so we can honor the resend throttle.
        let existing;
        try {
            existing = await store.get(key);
        }
        catch (cause) {
            throw new AuthKitError("store_failure", "OtpStore.get failed while starting an OTP", { cause });
        }
        // Throttle: if a STILL-LIVE code was issued within the throttle window,
        // refuse a resend and tell the caller how long to wait + when the EXISTING
        // code expires. The liveness gate (`now < existing.expiresAt`) is load-
        // bearing: without it, a config where resendThrottleSeconds > ttlSeconds
        // (nothing forbids that) — or a slow-evicting / clock-skewed store — could
        // throttle a resend whose code `verifyOtp` will immediately reject as
        // `expired`, a silent dead window where the caller can neither verify nor
        // resend. Gating on liveness means we only throttle a code that can still
        // be verified; an expired record falls through to a fresh send below.
        if (existing && now < existing.expiresAt) {
            const elapsed = now - existing.issuedAt;
            if (elapsed < cfg.resendThrottleSeconds) {
                return {
                    status: "throttled",
                    retryAfter: cfg.resendThrottleSeconds - elapsed,
                    expiresAt: existing.expiresAt,
                };
            }
        }
        // Generate a fresh code, store it HASHED (never plaintext), then deliver it.
        const code = codeGen.generate(cfg.length);
        const codeHash = await sha256Hex(code);
        const expiresAt = now + cfg.ttlSeconds;
        const record = {
            codeHash,
            expiresAt,
            issuedAt: now,
            attempts: 0,
        };
        try {
            // TTL = remaining lifetime so a native-TTL store self-evicts the record.
            await store.set(key, record, cfg.ttlSeconds);
        }
        catch (cause) {
            throw new AuthKitError("store_failure", "OtpStore.set failed while starting an OTP", { cause });
        }
        try {
            await sender.send({ to: normalized, code, ttlSeconds: cfg.ttlSeconds });
        }
        catch (cause) {
            // Leave the stored code in place (it self-evicts via the native TTL passed
            // to store.set) — do NOT delete it here. sender.send is not atomic: the
            // email may already be delivered when send() rejects (post-accept timeout /
            // connection drop), and a blind keyed consume would (a) make a delivered
            // code permanently unverifiable, (b) clobber a concurrent startOtp's record
            // (consume is a keyed delete, not compare-and-delete), and (c) drop the
            // resend-throttle state, enabling un-throttled retries. The code is stored
            // but possibly undeliverable — surface the fault rather than reporting sent
            // for an email that never went out.
            throw new AuthKitError("email_send_failure", "EmailSender.send failed while starting an OTP", { cause });
        }
        return { status: "sent", expiresAt };
    }
    async function verifyOtp(email, code) {
        const normalized = normalizeEmail(email);
        const key = otpKey(normalized);
        let record;
        try {
            record = await store.get(key);
        }
        catch (cause) {
            throw new AuthKitError("store_failure", "OtpStore.get failed while verifying an OTP", { cause });
        }
        // No active record: never started, already consumed, or store-evicted.
        // Defense-in-depth: do the SAME sha-256 + constant-time compare the
        // mismatch path does, against a fixed dummy hash, before returning. Without
        // this the not-found path returns measurably faster than a wrong-code path
        // (which hashes + compares), a timing side channel for record existence on
        // top of the explicit `reason`. We discard the result — it is always a
        // not-found. (Equalizing the store-write path is not worth it; maxAttempts
        // already bounds the brute-force surface.)
        if (record === null) {
            const dummyHash = await sha256Hex(code);
            constantTimeEqualHex(dummyHash, DUMMY_HASH);
            return { ok: false, reason: "not_found" };
        }
        // Core-enforced expiry against the Clock (a TTL-less store still works).
        // An expired record is dead — consume it so it cannot be retried.
        if (nowSec() >= record.expiresAt) {
            await consumeRecord(key, "verifying an expired OTP");
            return { ok: false, reason: "expired" };
        }
        // Constant-time hash compare against the stored sha-256 hex.
        const candidateHash = await sha256Hex(code);
        const matches = constantTimeEqualHex(candidateHash, record.codeHash);
        if (!matches) {
            // Consume one attempt; lock + destroy the record at maxAttempts.
            let attempts;
            try {
                attempts = await store.incrementAttempts(key);
            }
            catch (cause) {
                throw new AuthKitError("store_failure", "OtpStore.incrementAttempts failed while verifying an OTP", { cause });
            }
            if (attempts >= cfg.maxAttempts) {
                await consumeRecord(key, "locking an OTP after maxAttempts");
                return { ok: false, reason: "locked" };
            }
            return { ok: false, reason: "mismatch" };
        }
        // Match: single-use — consume before returning the verified identity.
        await consumeRecord(key, "consuming a verified OTP");
        return {
            ok: true,
            identity: {
                providerSubject: "email:" + normalized,
                email: normalized,
                emailVerified: true,
            },
        };
    }
    // consume() is documented idempotent; a store fault here is still an adapter
    // fault we surface rather than swallow.
    async function consumeRecord(key, ctx) {
        try {
            await store.consume(key);
        }
        catch (cause) {
            throw new AuthKitError("store_failure", `OtpStore.consume failed while ${ctx}`, { cause });
        }
    }
    return { startOtp, verifyOtp };
}
//# sourceMappingURL=email-otp.js.map