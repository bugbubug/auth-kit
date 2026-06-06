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
//# sourceMappingURL=crypto.d.ts.map