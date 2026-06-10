/**
 * Fetch-backed JwksSource — the ONLY real-egress adapter in the kit.
 *
 * Framework/runtime-agnostic: uses the standard `fetch` global (present in
 * Workers, Node 18+, Deno, browsers) and the injected Clock only — no
 * Workers/CF/Hono/Node imports. Fetches Google's JWKS, parses `{ keys }`, and
 * caches the key set honoring the response `Cache-Control: max-age` against the
 * injected clock so repeated verifications inside the window cause zero egress.
 *
 * Failure policy: a network error, non-2xx response, or unparseable body is a
 * programmer/infrastructure fault the caller cannot recover from at verify time,
 * so it throws AuthKitError("jwks_failure") (with the underlying cause attached)
 * rather than returning an empty set. Expected auth failures stay in the
 * verifier's discriminated union; this is not one of them.
 */

import type { Clock, Jwk, JwksSource } from "../ports.js";
import { AuthKitError } from "../types.js";
import { systemClock } from "../util.js";

/** Google's public OAuth2 JWKS endpoint. */
const DEFAULT_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";

/** Fallback cache lifetime (seconds) when the response carries no usable max-age. */
const FALLBACK_MAX_AGE_SECONDS = 3600;

/** Default whole-operation (fetch + body read) timeout in milliseconds. */
const DEFAULT_TIMEOUT_MS = 5000;

interface CacheEntry {
  keys: Jwk[];
  /** Absolute epoch-ms instant at which this cache entry expires. */
  expiresAtMs: number;
}

export interface FetchJwksOptions {
  /** Override the JWKS endpoint. Defaults to Google's certs URL. */
  url?: string;
  /** Injected time source (epoch ms). Defaults to systemClock. */
  clock?: Clock;
  /**
   * Whole-operation timeout in MILLISECONDS for a JWKS refresh — the
   * AbortController deadline that stays armed across both the `fetch` and the
   * response-body read. Defaults to 5000. Must be a positive integer when
   * provided, else AuthKitError("config_invalid") at construction.
   */
  timeoutMs?: number;
}

export class FetchJwksSource implements JwksSource {
  private readonly url: string;
  private readonly clock: Clock;
  private readonly timeoutMs: number;
  private cache: CacheEntry | null = null;
  /** De-dupes concurrent refreshes so a burst of verifies fires one fetch. */
  private inflight: Promise<{ keys: Jwk[] }> | null = null;

  constructor(opts?: FetchJwksOptions) {
    this.url = opts?.url ?? DEFAULT_JWKS_URL;
    this.clock = opts?.clock ?? systemClock;
    if (
      opts?.timeoutMs !== undefined &&
      (!Number.isInteger(opts.timeoutMs) || opts.timeoutMs <= 0)
    ) {
      throw new AuthKitError(
        "config_invalid",
        `FetchJwksOptions.timeoutMs must be a positive integer, got ${String(opts.timeoutMs)}`,
      );
    }
    this.timeoutMs = opts?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  async getKeys(): Promise<{ keys: Jwk[] }> {
    const now = this.clock.now();
    if (this.cache !== null && now < this.cache.expiresAtMs) {
      return { keys: [...this.cache.keys] };
    }

    // Collapse concurrent refreshes onto a single in-flight fetch.
    if (this.inflight !== null) return this.inflight;

    this.inflight = this.refresh()
      .finally(() => {
        this.inflight = null;
      });
    return this.inflight;
  }

  private async refresh(): Promise<{ keys: Jwk[] }> {
    // Keep the timeout (timeoutMs, default 5s) armed across the WHOLE
    // operation — both the fetch (headers) AND the body read — so a stalled
    // body can't hang past the deadline. A single clearTimeout in finally
    // disarms it after the body read completes or after any throw.
    let response: Response;
    let body: unknown;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      try {
        response = await fetch(this.url, {
          headers: { accept: "application/json" },
          signal: controller.signal,
        });
      } catch (cause) {
        throw new AuthKitError(
          "jwks_failure",
          `Failed to fetch JWKS from ${this.url}`,
          { cause },
        );
      }

      // Outside the body try/catch so this jwks_failure propagates unchanged
      // (it must NOT be remapped to the invalid-JSON message).
      if (!response.ok) {
        throw new AuthKitError(
          "jwks_failure",
          `JWKS endpoint ${this.url} returned HTTP ${response.status}`,
        );
      }

      try {
        // Still under the timeout: an AbortError here (stalled body) surfaces
        // as the invalid-JSON failure with the abort attached as the cause.
        body = await response.json();
      } catch (cause) {
        throw new AuthKitError(
          "jwks_failure",
          `JWKS response from ${this.url} was not valid JSON`,
          { cause },
        );
      }
    } finally {
      clearTimeout(timeoutId);
    }

    const keys = extractKeys(body);
    if (keys === null) {
      throw new AuthKitError(
        "jwks_failure",
        `JWKS response from ${this.url} did not contain a "keys" array`,
      );
    }

    const maxAge = parseMaxAge(response.headers.get("cache-control"));
    const ttlSeconds = maxAge ?? FALLBACK_MAX_AGE_SECONDS;
    this.cache = {
      keys,
      expiresAtMs: this.clock.now() + ttlSeconds * 1000,
    };

    return { keys: [...keys] };
  }
}

/** Pull a `{ keys: Jwk[] }` array out of an unknown JSON body, or null. */
function extractKeys(body: unknown): Jwk[] | null {
  if (
    typeof body !== "object" ||
    body === null ||
    !Array.isArray((body as { keys?: unknown }).keys)
  ) {
    return null;
  }
  return (body as { keys: Jwk[] }).keys;
}

/**
 * Extract `max-age` (seconds) from a Cache-Control header value, honoring a
 * `no-store`/`no-cache` directive (→ 0 so we never cache). Returns null when no
 * usable directive is present so the caller applies its fallback.
 */
function parseMaxAge(cacheControl: string | null): number | null {
  if (cacheControl === null) return null;
  const directives = cacheControl.toLowerCase().split(",");
  let maxAge: number | null = null;
  for (const raw of directives) {
    const directive = raw.trim();
    if (directive === "no-store" || directive === "no-cache") {
      return 0;
    }
    if (directive.startsWith("max-age=")) {
      const value = Number.parseInt(directive.slice("max-age=".length), 10);
      if (Number.isFinite(value) && value >= 0) {
        maxAge = value;
      }
    }
  }
  return maxAge;
}
