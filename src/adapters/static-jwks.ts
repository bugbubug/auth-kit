/**
 * Static JwksSource — the test/dev adapter for the JWKS port. Zero egress.
 *
 * Framework/runtime-agnostic: no Workers/CF/Hono/Node imports, no network. Tests
 * inject a fixed key set (e.g. the public half of a locally-generated RSA key)
 * so Google id_token verification runs entirely offline. The verifier selects the
 * signing key by `kid` from the returned set.
 */

import type { Jwk, JwksSource } from "../ports.js";

export class StaticJwksSource implements JwksSource {
  private readonly keys: Jwk[];

  /** @param keys the fixed JWKS to serve on every `getKeys` call. */
  constructor(keys: Jwk[]) {
    // Defensive copy so a later mutation of the caller's array cannot alter the
    // served key set.
    this.keys = [...keys];
  }

  async getKeys(): Promise<{ keys: Jwk[] }> {
    // Return a fresh array each call so a consumer cannot mutate our backing store.
    return { keys: [...this.keys] };
  }
}
