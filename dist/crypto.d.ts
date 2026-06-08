/**
 * WebCrypto-only primitives. Runs unchanged in Cloudflare Workers,
 * vitest-pool-workers, and Node 24 — uses `globalThis.crypto` exclusively, NEVER
 * `node:crypto`, so the core stays runtime-agnostic.
 */
import type { CodeGenerator } from "./ports.js";
/**
 * sha-256 of a UTF-8 string, lowercase hex. Used to store OTP codes hashed
 * (never plaintext) so a store breach does not leak live codes.
 */
export declare function sha256Hex(input: string): Promise<string>;
/**
 * Constant-time comparison of two hex strings. Length-mismatch returns false
 * immediately (the lengths are not secret — both are fixed-width sha-256 hex);
 * for equal lengths every character is compared so total work does not depend on
 * the position of the first differing nibble, removing a timing oracle on the
 * stored OTP hash.
 */
export declare function constantTimeEqualHex(a: string, b: string): boolean;
/**
 * WebCrypto-backed default CodeGenerator. Produces a uniformly-distributed
 * numeric string of exactly `length` digits, zero-padded.
 *
 * Uniformity: each digit is drawn 0–9 via rejection sampling over a single
 * random byte. A byte is 0–255; 250 = 25 * 10 is the largest multiple of 10 not
 * exceeding 256, so bytes in [250, 255] are REJECTED and re-drawn. This removes
 * the modulo bias that a naive `byte % 10` would introduce (values 0–5 would
 * otherwise be slightly over-represented). Bytes are pulled in bulk and the pool
 * is refilled on exhaustion, so the loop terminates with probability 1.
 */
export declare const defaultCodeGenerator: CodeGenerator;
/** PBKDF2-HMAC-SHA256 tunables. All optional; defaults match the locked spec. */
export interface PasswordHashConfig {
    /**
     * PBKDF2 iteration count. Default 100000 — the MAX Cloudflare Workers' WebCrypto
     * allows (`crypto.subtle.deriveBits` throws `NotSupportedError` above 100000), so
     * it stays portable across Workers/Node/bun. Node-only consumers can pass a higher
     * value (e.g. OWASP 2023's 600000); verifyPassword reads the count back from the
     * stored string, so any value round-trips.
     */
    iterations?: number;
    /** Random salt length in bytes. Default 16. */
    saltBytes?: number;
    /** Derived key length in bytes. Default 32. */
    keyBytes?: number;
}
/**
 * The applied (no-undefined) password-hash config. The default `iterations`
 * (100000) is the MAXIMUM Cloudflare Workers' WebCrypto permits for PBKDF2 —
 * `crypto.subtle.deriveBits` throws `NotSupportedError: iteration counts above
 * 100000 are not supported` for anything higher — so this is the highest value that
 * runs UNCHANGED on Workers, Node, and bun (the kit's portability rule). OWASP
 * 2023's 600000 floor is unreachable on Workers; a Node-only consumer that wants it
 * can pass `{ iterations: 600_000 }` explicitly. `verifyPassword` parses the count
 * back from the self-describing hash string, so changing this never breaks old hashes.
 */
export declare const PASSWORD_HASH_DEFAULTS: Required<PasswordHashConfig>;
/**
 * Hash a password with PBKDF2-HMAC-SHA256, returning a SELF-DESCRIBING string:
 * `pbkdf2-sha256$<iterations>$<saltHex>$<hashHex>` (lowercase hex). A fresh
 * random salt is drawn per call, so two hashes of the same password differ.
 *
 * Throws `RangeError` for programmer misuse — a non-string/empty password or a
 * non-positive-integer config value — consistent with `defaultCodeGenerator`.
 */
export declare function hashPassword(password: string, config?: PasswordHashConfig): Promise<string>;
/**
 * Verify a password against a `stored` hash produced by `hashPassword`. Re-derives
 * with the salt + iteration count parsed FROM the stored string (so a hash made
 * with non-default iterations still verifies), and compares constant-time via
 * `constantTimeEqualHex`.
 *
 * NEVER throws: returns `false` on any malformed `stored` string or any failed
 * derivation, so a corrupt/legacy value can't crash the login path.
 */
export declare function verifyPassword(password: string, stored: string): Promise<boolean>;
//# sourceMappingURL=crypto.d.ts.map