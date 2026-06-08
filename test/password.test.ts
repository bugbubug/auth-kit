/**
 * Password hashing primitive tests — fully deterministic, zero egress.
 *
 * Covers the PBKDF2-HMAC-SHA256 primitives (pure WebCrypto, no storage): the
 * self-describing hash format, round-trip verify (correct/wrong), per-call random
 * salt (two hashes of the same password differ yet both verify), tamper rejection,
 * malformed-`stored` rejection WITHOUT throwing, unicode/long passwords, and the
 * parse-iterations-from-string invariant (a non-default-iteration hash verifies).
 *
 * Most tests pass {iterations: 1000} for speed; one default-iteration round-trip
 * exercises the real default (100000-iteration) cost.
 */

import { describe, expect, it } from "bun:test";

import {
  hashPassword,
  verifyPassword,
  PASSWORD_HASH_DEFAULTS,
} from "../src/crypto.js";

const FAST = { iterations: 1000 } as const;
const PW = "correct horse battery staple";

describe("password — hashPassword", () => {
  it("returns a self-describing pbkdf2-sha256 string, never the plaintext", async () => {
    const stored = await hashPassword(PW, FAST);

    expect(stored).not.toBe(PW);
    expect(stored).not.toContain(PW);
    // pbkdf2-sha256$<iters>$<saltHex>$<hashHex>
    expect(stored).toMatch(
      /^pbkdf2-sha256\$1000\$[0-9a-f]{32}\$[0-9a-f]{64}$/,
    );
    const parts = stored.split("$");
    expect(parts).toHaveLength(4);
    expect(parts[0]).toBe("pbkdf2-sha256");
    expect(parts[1]).toBe("1000");
    // default saltBytes=16 -> 32 hex chars; keyBytes=32 -> 64 hex chars.
    expect(parts[2]).toHaveLength(PASSWORD_HASH_DEFAULTS.saltBytes * 2);
    expect(parts[3]).toHaveLength(PASSWORD_HASH_DEFAULTS.keyBytes * 2);
  });

  it("draws a fresh random salt per call: two hashes of the same password differ, yet both verify", async () => {
    const a = await hashPassword(PW, FAST);
    const b = await hashPassword(PW, FAST);

    expect(a).not.toBe(b);
    expect(await verifyPassword(PW, a)).toBe(true);
    expect(await verifyPassword(PW, b)).toBe(true);
  });

  it("rejects a non-string / empty password with RangeError (programmer misuse)", async () => {
    await expect(hashPassword("", FAST)).rejects.toBeInstanceOf(RangeError);
    // @ts-expect-error — deliberately wrong type for the runtime guard.
    await expect(hashPassword(undefined, FAST)).rejects.toBeInstanceOf(
      RangeError,
    );
    // @ts-expect-error — deliberately wrong type for the runtime guard.
    await expect(hashPassword(123, FAST)).rejects.toBeInstanceOf(RangeError);
  });

  it("rejects non-positive-integer config values with RangeError", async () => {
    await expect(hashPassword(PW, { iterations: 0 })).rejects.toBeInstanceOf(
      RangeError,
    );
    await expect(hashPassword(PW, { iterations: -1 })).rejects.toBeInstanceOf(
      RangeError,
    );
    await expect(hashPassword(PW, { iterations: 1.5 })).rejects.toBeInstanceOf(
      RangeError,
    );
    await expect(hashPassword(PW, { saltBytes: 0 })).rejects.toBeInstanceOf(
      RangeError,
    );
    await expect(hashPassword(PW, { keyBytes: 0 })).rejects.toBeInstanceOf(
      RangeError,
    );
  });
});

describe("password — verifyPassword", () => {
  it("verify(correct) === true, verify(wrong) === false", async () => {
    const stored = await hashPassword(PW, FAST);

    expect(await verifyPassword(PW, stored)).toBe(true);
    expect(await verifyPassword("wrong password", stored)).toBe(false);
    // Off-by-one on the password is also rejected.
    expect(await verifyPassword(PW + " ", stored)).toBe(false);
  });

  it("a hash made with NON-default iterations still verifies (parsed from the string)", async () => {
    const stored = await hashPassword(PW, { iterations: 2048 });
    expect(stored).toContain("$2048$");
    expect(await verifyPassword(PW, stored)).toBe(true);
    expect(await verifyPassword("nope", stored)).toBe(false);
  });

  it("a tampered hash hex -> false", async () => {
    const stored = await hashPassword(PW, FAST);
    const parts = stored.split("$");
    const hashHex = parts[3] ?? "";
    // Flip the first hex nibble of the derived hash.
    const flipped = (hashHex[0] === "0" ? "1" : "0") + hashHex.slice(1);
    const tampered = `${parts[0]}$${parts[1]}$${parts[2]}$${flipped}`;
    expect(tampered).not.toBe(stored);
    expect(await verifyPassword(PW, tampered)).toBe(false);
  });

  it("malformed stored strings -> false, never throw", async () => {
    const cases = [
      "", // empty
      "plaintext", // no separators
      "sha256$1000$aa$bb", // wrong scheme
      "pbkdf2-sha256$1000$aa", // missing parts (3, not 4)
      "pbkdf2-sha256$1000$aa$bb$cc", // too many parts
      "pbkdf2-sha256$0$aa$bb", // non-positive iterations
      "pbkdf2-sha256$-5$aa$bb", // negative iterations
      "pbkdf2-sha256$1e3$aa$bb", // non-decimal iterations
      "pbkdf2-sha256$1000$ZZ$bb", // non-hex salt
      "pbkdf2-sha256$1000$aa$ZZ", // non-hex hash
      "pbkdf2-sha256$1000$abc$bb", // odd-length salt hex
      "pbkdf2-sha256$1000$aa$abc", // odd-length hash hex
      "pbkdf2-sha256$1000$$", // empty salt + hash (and only 3 parts effectively)
      "pbkdf2-sha256$1000$aa$BB", // uppercase hex (we require lowercase)
    ];
    for (const stored of cases) {
      expect(await verifyPassword(PW, stored)).toBe(false);
    }
  });

  it("non-string stored / password -> false, never throw", async () => {
    // @ts-expect-error — deliberately wrong type for the runtime guard.
    expect(await verifyPassword(PW, undefined)).toBe(false);
    // @ts-expect-error — deliberately wrong type for the runtime guard.
    expect(await verifyPassword(PW, 123)).toBe(false);
    const stored = await hashPassword(PW, FAST);
    // @ts-expect-error — deliberately wrong type for the runtime guard.
    expect(await verifyPassword(undefined, stored)).toBe(false);
  });

  it("handles unicode and long passwords (round-trip)", async () => {
    const unicode = "пароль🔐密码—café";
    const long = "x".repeat(200);
    const uStored = await hashPassword(unicode, FAST);
    const lStored = await hashPassword(long, FAST);

    expect(await verifyPassword(unicode, uStored)).toBe(true);
    expect(await verifyPassword("password", uStored)).toBe(false);
    expect(await verifyPassword(long, lStored)).toBe(true);
    expect(await verifyPassword("x".repeat(199), lStored)).toBe(false);
  });

  it("a default-iteration (100000) round-trip still verifies", async () => {
    // The one real-cost test: prove the defaults are wired and round-trip.
    const stored = await hashPassword(PW);
    expect(stored).toContain(`$${PASSWORD_HASH_DEFAULTS.iterations}$`);
    expect(await verifyPassword(PW, stored)).toBe(true);
    expect(await verifyPassword("wrong", stored)).toBe(false);
  });
});
