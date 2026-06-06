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
import type { Clock, OtpRecord, OtpStore } from "../ports.js";
export declare class InMemoryOtpStore implements OtpStore {
    private readonly clock;
    private readonly entries;
    /**
     * @param clock injected time source (epoch ms). Defaults to systemClock so
     *   tests can pass a fixed Clock for deterministic eviction.
     */
    constructor(clock?: Clock);
    get(key: string): Promise<OtpRecord | null>;
    set(key: string, value: OtpRecord, ttlSeconds: number): Promise<void>;
    incrementAttempts(key: string): Promise<number>;
    consume(key: string): Promise<void>;
}
//# sourceMappingURL=memory-otp-store.d.ts.map