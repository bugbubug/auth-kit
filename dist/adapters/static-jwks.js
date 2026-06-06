/**
 * Static JwksSource — the test/dev adapter for the JWKS port. Zero egress.
 *
 * Framework/runtime-agnostic: no Workers/CF/Hono/Node imports, no network. Tests
 * inject a fixed key set (e.g. the public half of a locally-generated RSA key)
 * so Google id_token verification runs entirely offline. The verifier selects the
 * signing key by `kid` from the returned set.
 */
export class StaticJwksSource {
    keys;
    /** @param keys the fixed JWKS to serve on every `getKeys` call. */
    constructor(keys) {
        // Defensive copy so a later mutation of the caller's array cannot alter the
        // served key set.
        this.keys = [...keys];
    }
    async getKeys() {
        // Return a fresh array each call so a consumer cannot mutate our backing store.
        return { keys: [...this.keys] };
    }
}
//# sourceMappingURL=static-jwks.js.map