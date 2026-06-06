/**
 * In-memory OtpStore — the test/dev adapter for the Email OTP persistence port.
 *
 * Framework/runtime-agnostic: backed by a plain `Map`, no Workers/CF/Hono/Node
 * imports. Zero egress. The `set` contract carries `ttlSeconds` (remaining
 * lifetime); a real KV would forward it to `put(..., { expirationTtl })`. Here we
 * translate it into an ABSOLUTE eviction deadline in epoch MILLISECONDS using the
 * injected Clock, so `get` self-evicts expired records exactly like a TTL-store —
 * and stays deterministic under a fixed test clock. (The core ALSO enforces
 * expiry against its own Clock, so this eviction is belt-and-suspenders.)
 */
import { systemClock } from "../util.js";
export class InMemoryOtpStore {
    clock;
    entries = new Map();
    /**
     * @param clock injected time source (epoch ms). Defaults to systemClock so
     *   tests can pass a fixed Clock for deterministic eviction.
     */
    constructor(clock = systemClock) {
        this.clock = clock;
    }
    async get(key) {
        const entry = this.entries.get(key);
        if (entry === undefined)
            return null;
        // Self-evict once the absolute deadline has passed (>=, not >).
        if (this.clock.now() >= entry.evictAtMs) {
            this.entries.delete(key);
            return null;
        }
        return entry.record;
    }
    async set(key, value, ttlSeconds) {
        const evictAtMs = this.clock.now() + ttlSeconds * 1000;
        // Store a shallow copy so a later mutation of the caller's object cannot
        // retroactively change the persisted record.
        this.entries.set(key, { record: { ...value }, evictAtMs });
    }
    async incrementAttempts(key) {
        const entry = this.entries.get(key);
        if (entry === undefined) {
            // No active record — nothing to increment. Treat as zero attempts so the
            // caller does not crash on a race where the record was just consumed.
            return 0;
        }
        entry.record.attempts += 1;
        return entry.record.attempts;
    }
    async consume(key) {
        // Idempotent: deleting an absent key is a no-op.
        this.entries.delete(key);
    }
}
//# sourceMappingURL=memory-otp-store.js.map