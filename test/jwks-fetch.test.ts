/**
 * FetchJwksSource timeout tests — zero REAL egress. The behavioral case stubs
 * the global `fetch` with a never-resolving promise that rejects only when the
 * adapter's AbortSignal fires, proving the configurable timeoutMs deadline
 * actually aborts a stalled fetch and surfaces AuthKitError("jwks_failure")
 * with the abort attached as the cause.
 *
 * Construction-time validation: timeoutMs must be a positive integer when
 * provided (else AuthKitError("config_invalid")); omitted -> the 5000ms
 * default (asserted via construction not throwing).
 */

import { afterEach, describe, expect, it } from "bun:test";

import { FetchJwksSource } from "../src/adapters/jwks-fetch.js";
import { AuthKitError } from "../src/types.js";

const realFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = realFetch;
});

describe("FetchJwksSource — timeoutMs validation", () => {
  it("constructs with no options (default timeout 5000) without throwing", () => {
    expect(() => new FetchJwksSource()).not.toThrow();
    expect(() => new FetchJwksSource({ url: "https://example.com/jwks" })).not.toThrow();
  });

  it("constructs with a valid positive-integer timeoutMs without throwing", () => {
    expect(() => new FetchJwksSource({ timeoutMs: 1 })).not.toThrow();
    expect(() => new FetchJwksSource({ timeoutMs: 5000 })).not.toThrow();
    expect(() => new FetchJwksSource({ timeoutMs: 30_000 })).not.toThrow();
  });

  it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])(
    "throws config_invalid for timeoutMs = %p",
    (bad) => {
      let caught: unknown;
      try {
        new FetchJwksSource({ timeoutMs: bad as number });
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(AuthKitError);
      expect((caught as AuthKitError).code).toBe("config_invalid");
      expect((caught as AuthKitError).message).toContain(
        "FetchJwksOptions.timeoutMs must be a positive integer",
      );
    },
  );
});

describe("FetchJwksSource — timeout behavior", () => {
  it("aborts a stalled fetch after timeoutMs and surfaces jwks_failure with the abort as cause", async () => {
    // A fetch that NEVER resolves on its own; it only rejects when the
    // adapter's timeout fires the AbortSignal — exactly a stalled endpoint.
    let sawSignal = false;
    globalThis.fetch = ((_input: unknown, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        const signal = init?.signal;
        if (!signal) return; // would hang forever — the assertion below catches it
        sawSignal = true;
        signal.addEventListener("abort", () => {
          reject(signal.reason ?? new Error("aborted"));
        });
      })) as typeof fetch;

    const source = new FetchJwksSource({
      url: "https://stalled.example.com/jwks",
      timeoutMs: 30,
    });

    let caught: unknown;
    try {
      await source.getKeys();
    } catch (e) {
      caught = e;
    }

    expect(sawSignal).toBe(true);
    expect(caught).toBeInstanceOf(AuthKitError);
    const err = caught as AuthKitError;
    expect(err.code).toBe("jwks_failure");
    expect(err.message).toContain("Failed to fetch JWKS");
    // The abort reason (a DOMException named AbortError) rides along as cause.
    expect(err.cause).toBeDefined();
    expect((err.cause as Error).name).toBe("AbortError");
  });
});
