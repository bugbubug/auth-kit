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
  // Iterate values (not indices) so each `byte` is a plain `number` from the
  // Uint8Array iterator — no index access, no noUncheckedIndexedAccess narrowing.
  for (const byte of view) {
    hex += byte.toString(16).padStart(2, "0");
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
      // The refill guard above guarantees `cursor` is in-bounds when read, so
      // this never triggers; the explicit guard narrows `number | undefined` to
      // `number` without a non-null assertion (and costs nothing at runtime).
      if (byte === undefined) continue;
      if (byte < limit) {
        digits.push(byte % 10);
      }
      // else: reject (modulo bias guard) and draw the next byte.
    }

    return digits.join("");
  },
};

// ─── Password hashing (PBKDF2-HMAC-SHA256, pure WebCrypto) ───────────────────
//
// PURE primitives only: hash and verify a password. Storage + orchestration
// (register/login/reset, the users row, throttling) stay in the consumer — the
// kit never owns those (mirrors the OTP/Google "verify only" boundary). The
// hash is a SELF-DESCRIBING string ("pbkdf2-sha256$<iters>$<saltHex>$<hashHex>")
// so verify re-derives with the exact parameters that produced it — no separate
// columns, and the iteration count can be raised later without breaking old hashes.

/** PBKDF2-HMAC-SHA256 tunables. All optional; defaults match the locked spec. */
export interface PasswordHashConfig {
  /** PBKDF2 iteration count. Default 600000 (OWASP 2023 floor). */
  iterations?: number;
  /** Random salt length in bytes. Default 16. */
  saltBytes?: number;
  /** Derived key length in bytes. Default 32. */
  keyBytes?: number;
}

/**
 * The applied (no-undefined) password-hash config. The default `iterations`
 * (600000) is the OWASP 2023 floor for PBKDF2-HMAC-SHA256.
 */
export const PASSWORD_HASH_DEFAULTS: Required<PasswordHashConfig> = {
  iterations: 600_000,
  saltBytes: 16,
  keyBytes: 32,
};

/** Lowercase-hex encode a byte array (no index access; iterates values). */
function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

/**
 * Decode an even-length lowercase-hex string to bytes. Returns null on any
 * malformed input (odd length, or a non-hex character) so callers can fail
 * closed instead of throwing.
 */
function hexToBytes(hex: string): Uint8Array<ArrayBuffer> | null {
  if (hex.length % 2 !== 0) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) return null;
    out[i] = byte;
  }
  return out;
}

/** Derive `keyBytes` bytes from a password + salt via PBKDF2-HMAC-SHA256. */
async function deriveBitsHex(
  password: string,
  salt: Uint8Array<ArrayBuffer>,
  iterations: number,
  keyBytes: number,
): Promise<string> {
  const passwordBytes = new TextEncoder().encode(password);
  const key = await globalThis.crypto.subtle.importKey(
    "raw",
    passwordBytes,
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await globalThis.crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    key,
    keyBytes * 8,
  );
  return bytesToHex(new Uint8Array(bits));
}

/**
 * Hash a password with PBKDF2-HMAC-SHA256, returning a SELF-DESCRIBING string:
 * `pbkdf2-sha256$<iterations>$<saltHex>$<hashHex>` (lowercase hex). A fresh
 * random salt is drawn per call, so two hashes of the same password differ.
 *
 * Throws `RangeError` for programmer misuse — a non-string/empty password or a
 * non-positive-integer config value — consistent with `defaultCodeGenerator`.
 */
export async function hashPassword(
  password: string,
  config?: PasswordHashConfig,
): Promise<string> {
  if (typeof password !== "string" || password.length === 0) {
    throw new RangeError("hashPassword: password must be a non-empty string");
  }
  const iterations = config?.iterations ?? PASSWORD_HASH_DEFAULTS.iterations;
  const saltBytes = config?.saltBytes ?? PASSWORD_HASH_DEFAULTS.saltBytes;
  const keyBytes = config?.keyBytes ?? PASSWORD_HASH_DEFAULTS.keyBytes;
  for (const [name, value] of [
    ["iterations", iterations],
    ["saltBytes", saltBytes],
    ["keyBytes", keyBytes],
  ] as const) {
    if (!Number.isInteger(value) || value <= 0) {
      throw new RangeError(
        `hashPassword: ${name} must be a positive integer, got ${String(value)}`,
      );
    }
  }

  const salt = new Uint8Array(saltBytes);
  globalThis.crypto.getRandomValues(salt);
  const hashHex = await deriveBitsHex(password, salt, iterations, keyBytes);
  return `pbkdf2-sha256$${iterations}$${bytesToHex(salt)}$${hashHex}`;
}

/**
 * Verify a password against a `stored` hash produced by `hashPassword`. Re-derives
 * with the salt + iteration count parsed FROM the stored string (so a hash made
 * with non-default iterations still verifies), and compares constant-time via
 * `constantTimeEqualHex`.
 *
 * NEVER throws: returns `false` on any malformed `stored` string or any failed
 * derivation, so a corrupt/legacy value can't crash the login path.
 */
export async function verifyPassword(
  password: string,
  stored: string,
): Promise<boolean> {
  if (typeof password !== "string" || typeof stored !== "string") return false;

  const parts = stored.split("$");
  if (parts.length !== 4) return false;
  const [scheme, iterationsRaw, saltHex, hashHex] = parts;
  // Under noUncheckedIndexedAccess each part is `string | undefined`; guard each.
  if (!scheme || !iterationsRaw || !saltHex || !hashHex) return false;
  if (scheme !== "pbkdf2-sha256") return false;
  if (!/^[1-9][0-9]*$/.test(iterationsRaw)) return false;
  const iterations = Number.parseInt(iterationsRaw, 10);
  if (!Number.isInteger(iterations) || iterations <= 0) return false;
  if (!/^[0-9a-f]+$/.test(saltHex) || saltHex.length % 2 !== 0) return false;
  if (!/^[0-9a-f]+$/.test(hashHex) || hashHex.length % 2 !== 0) return false;

  const salt = hexToBytes(saltHex);
  if (salt === null) return false;
  const keyBytes = hashHex.length / 2;

  try {
    const actualHex = await deriveBitsHex(password, salt, iterations, keyBytes);
    return constantTimeEqualHex(actualHex, hashHex);
  } catch {
    return false;
  }
}
