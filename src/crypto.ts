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
export async function sha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  const view = new Uint8Array(digest);
  let hex = "";
  for (let i = 0; i < view.length; i++) {
    hex += view[i].toString(16).padStart(2, "0");
  }
  return hex;
}

/**
 * Constant-time comparison of two hex strings. Length-mismatch returns false
 * immediately (the lengths are not secret — both are fixed-width sha-256 hex);
 * for equal lengths every character is compared so total work does not depend on
 * the position of the first differing nibble, removing a timing oracle on the
 * stored OTP hash.
 */
export function constantTimeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

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
export const defaultCodeGenerator: CodeGenerator = {
  generate(length: number): string {
    if (!Number.isInteger(length) || length <= 0) {
      throw new RangeError(
        `defaultCodeGenerator.generate: length must be a positive integer, got ${String(length)}`,
      );
    }

    // Largest multiple of 10 that fits in a byte; bytes >= this are rejected.
    const limit = 250; // 25 * 10
    const digits: number[] = [];

    // Over-provision the random pool to reduce subtle.* calls; refill if needed.
    let pool = new Uint8Array(length * 2);
    globalThis.crypto.getRandomValues(pool);
    let cursor = 0;

    while (digits.length < length) {
      if (cursor >= pool.length) {
        pool = new Uint8Array(length * 2);
        globalThis.crypto.getRandomValues(pool);
        cursor = 0;
      }
      const byte = pool[cursor++];
      if (byte < limit) {
        digits.push(byte % 10);
      }
      // else: reject (modulo bias guard) and draw the next byte.
    }

    return digits.join("");
  },
};
