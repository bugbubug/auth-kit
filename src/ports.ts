/**
 * PORTS — the consumer injects an adapter for each. Adapters MAY be CF-specific;
 * the core never knows. Frozen baseline: etc/auth-kit.api.md (the port shapes).
 *
 * No implementations live here — only the interfaces the hexagonal core depends
 * on. Built-in default impls (defaultCodeGenerator, systemClock) live in
 * ./crypto and ./util; optional CF/test adapters live in ./adapters.
 */

/** Monotonic time source. Inject a fixed clock in tests for determinism. */
export interface Clock {
  /** Current time in Unix epoch MILLISECONDS (matches Date.now()). */
  now(): number;
}

/** Generates the OTP code. Default impl uses crypto.getRandomValues. */
export interface CodeGenerator {
  /** Return a numeric string of exactly `length` digits (zero-padded). */
  generate(length: number): string;
}

/**
 * The record the OtpStore persists per email. Opaque to adapters except they
 * must round-trip every field. The core stores the code HASHED (sha-256 hex),
 * never plaintext, so a store breach does not leak live codes.
 */
export interface OtpRecord {
  /** sha-256(code) as lowercase hex. The plaintext code is never stored. */
  codeHash: string;
  /** Unix epoch SECONDS the code expires. The store SHOULD also TTL itself. */
  expiresAt: number;
  /** Unix epoch SECONDS the code was issued (drives the resend throttle). */
  issuedAt: number;
  /** Attempts consumed so far against this code. */
  attempts: number;
}

/**
 * Persistence port for Email OTP. A KV namespace (CF) or a D1 table both satisfy
 * it; tests inject an in-memory map. Keys are derived by the core from the
 * normalized email (the consumer never builds keys). TTL semantics: `set` SHOULD
 * apply a native TTL of (expiresAt - now) so abandoned codes self-evict, but the
 * core ALSO enforces expiry against the Clock so a TTL-less store still works.
 */
export interface OtpStore {
  /** Fetch the active record for `key`, or null if absent/evicted. */
  get(key: string): Promise<OtpRecord | null>;
  /**
   * Write/overwrite the active record. `ttlSeconds` is the remaining lifetime;
   * KV adapters pass it to `put(..., { expirationTtl })`. Throw → AuthKitError.
   */
  set(key: string, value: OtpRecord, ttlSeconds: number): Promise<void>;
  /**
   * Atomically increment `attempts` and return the NEW count. Used on each
   * mismatch so the core can lock at maxAttempts without a read-modify-write
   * race. The increment MUST be atomic for the maxAttempts lock to be strict:
   * the core gates on the returned count (`>= maxAttempts`), so a lost update
   * lets effective guesses exceed maxAttempts within one code lifetime.
   *
   * NOTE: `verifyOtp` is NOT rate-limited by the resend throttle — the throttle
   * only governs `startOtp`. An attacker can fire unlimited CONCURRENT verifies
   * for one email without ever calling `startOtp`. So a KV adapter that emulates
   * this via read-modify-write `set` (last-writer-wins) is genuinely unsafe:
   * concurrent wrong guesses can collapse to a single increment. A KV-backed
   * adapter MUST use an atomic primitive (Durable Object, or D1
   * `UPDATE ... SET attempts = attempts + 1 RETURNING`, or a CAS/conditional
   * write), NOT a plain read-modify-write. The in-memory Map adapter shipped
   * here is atomic per microtask and therefore correct.
   */
  incrementAttempts(key: string): Promise<number>;
  /** Delete the record (called on success and on lock). Idempotent. */
  consume(key: string): Promise<void>;
}

/** The rendered email the core hands the sender. */
export interface OtpEmail {
  /** Normalized recipient address. */
  to: string;
  /** The 6-digit (or configured-length) code, plaintext, for the body. */
  code: string;
  /** Seconds until expiry, for copy like "expires in 10 minutes". */
  ttlSeconds: number;
}

/**
 * Outbound email port. The CF adapter wraps the `send_email` Workers binding;
 * the dev/test adapter is a no-op (or records to an array) for zero egress.
 * Throw → AuthKitError("email_send_failure"); the core surfaces it rather than
 * silently reporting "sent".
 */
export interface EmailSender {
  /** Render-and-send. The core supplies code+ttl; the adapter owns the template. */
  send(email: OtpEmail): Promise<void>;
}

/** A JSON Web Key (the subset the verifier needs; pass-through to `jose`). */
export interface Jwk {
  kid?: string;
  kty: string;
  alg?: string;
  use?: string;
  n?: string;
  e?: string;
  [claim: string]: unknown;
}

/**
 * Source of Google's public signing keys. The real adapter fetches Google's
 * JWKS (`https://www.googleapis.com/oauth2/v3/certs`) and caches per the
 * `Cache-Control` max-age — egress happens ONLY here, ONLY when verifying for
 * real. Tests inject a static key set (zero egress). The verifier selects the
 * key by `kid`.
 */
export interface JwksSource {
  /** Return the current key set. May fetch+cache, or return an injected static set. */
  getKeys(): Promise<{ keys: Jwk[] }>;
}
