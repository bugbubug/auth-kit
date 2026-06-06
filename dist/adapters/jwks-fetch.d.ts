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
export interface FetchJwksOptions {
    /** Override the JWKS endpoint. Defaults to Google's certs URL. */
    url?: string;
    /** Injected time source (epoch ms). Defaults to systemClock. */
    clock?: Clock;
}
export declare class FetchJwksSource implements JwksSource {
    private readonly url;
    private readonly clock;
    private cache;
    /** De-dupes concurrent refreshes so a burst of verifies fires one fetch. */
    private inflight;
    constructor(opts?: FetchJwksOptions);
    getKeys(): Promise<{
        keys: Jwk[];
    }>;
    private refresh;
}
//# sourceMappingURL=jwks-fetch.d.ts.map