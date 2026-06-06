/**
 * Static JwksSource — the test/dev adapter for the JWKS port. Zero egress.
 *
 * Framework/runtime-agnostic: no Workers/CF/Hono/Node imports, no network. Tests
 * inject a fixed key set (e.g. the public half of a locally-generated RSA key)
 * so Google id_token verification runs entirely offline. The verifier selects the
 * signing key by `kid` from the returned set.
 */
import type { Jwk, JwksSource } from "../ports.js";
export declare class StaticJwksSource implements JwksSource {
    private readonly keys;
    /** @param keys the fixed JWKS to serve on every `getKeys` call. */
    constructor(keys: Jwk[]);
    getKeys(): Promise<{
        keys: Jwk[];
    }>;
}
//# sourceMappingURL=static-jwks.d.ts.map