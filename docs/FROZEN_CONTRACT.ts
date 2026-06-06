/**
 * @bugbubug/auth-kit — FROZEN PUBLIC CONTRACT (v1).
 *
 * Pure, framework/runtime-agnostic TypeScript. NO Hono / Workers / Node imports
 * in this core surface — it runs in-process inside any consumer Worker today and
 * can later be wrapped as an HTTP service unchanged. Hexagonal: CORE owns the
 * deterministic flow; the CONSUMER injects ADAPTERS through the PORTS below.
 *
 * Two methods only: Email OTP and Google-id_token verification. Both return a
 * single VerifiedIdentity. The SDK ONLY verifies control of an identifier — it
 * never decides users/sessions/register-vs-login, never sets cookies, never
 * stores user rows. Account-linking POLICY stays in the app.
 *
 * zod: this surface is zod-free at the type level (plain TS interfaces, no
 * runtime validation forced on the consumer). zod is an OPTIONAL peerDependency
 * pinned to the SAME range emo uses ("^3.24.1") and is used only inside the
 * input-parsing helpers in `@bugbubug/auth-kit/zod` (a separate, non-frozen
 * subpath). The frozen core does not import zod, so a consumer on a different
 * zod minor is never broken by the engine.
 */

// ───────────────────────────────────────────────────────────────────────────
// 1. The single output type. Maps 1:1 onto emo's IdentityProvider.IdentityResult.
// ───────────────────────────────────────────────────────────────────────────

/**
 * The verified read of the principal behind a proven identifier. This is the
 * ONLY success payload either method returns.
 *
 * emo glue (near-zero) — given `id: VerifiedIdentity`, emo builds its
 * IdentityResult as:
 *   { providerSubject: id.providerSubject,
 *     profile: { email: id.email, displayName: id.displayName } }
 */
export interface VerifiedIdentity {
  /**
   * The provider's stable, opaque subject for this principal. Maps directly to
   * emo's `IdentityResult.providerSubject` and is the key in emo's
   * (productId, provider, providerSubject) unique index.
   *   • Email OTP: `email:<normalizedEmail>` (control of the address IS the id).
   *   • Google:    `google:<sub>` (Google's stable `sub` claim, NEVER the email).
   * The `<provider>:` prefix is part of the frozen format so two methods that
   * resolve the same human never collide on a bare value.
   */
  providerSubject: string;
  /**
   * The address, ALWAYS normalized: trimmed + lowercased. For Email OTP this is
   * the verified address; for Google it is the `email` claim (only present when
   * emailVerified is true — see below).
   */
  email: string;
  /**
   * Whether the email is provider-verified.
   *   • Email OTP: always `true` (control of the inbox was just proven).
   *   • Google: mirrors the `email_verified` claim; the verifier REQUIRES it to
   *     be true to succeed, so in practice this is always `true` on success. It
   *     is surfaced explicitly so emo's account-linking policy reads it directly
   *     rather than re-deriving it.
   */
  emailVerified: boolean;
  /** Optional human-friendly name (Google `name` claim; absent for Email OTP). */
  displayName?: string;
}

// ───────────────────────────────────────────────────────────────────────────
// 2. Result model — discriminated unions for EXPECTED outcomes (no throwing).
//    Programmer/config errors (missing deps, malformed config) throw AuthKitError.
// ───────────────────────────────────────────────────────────────────────────

/** Why an Email OTP start could not proceed normally. */
export type StartOtpResult =
  | {
      status: "sent";
      /** Unix epoch SECONDS at which the active code expires. */
      expiresAt: number;
    }
  | {
      status: "throttled";
      /** Seconds the caller must wait before another send is allowed (resend throttle). */
      retryAfter: number;
      /** Unix epoch SECONDS at which the EXISTING (still-valid) code expires. */
      expiresAt: number;
    };

/** Why an Email OTP verify failed (expected, caller-recoverable). */
export type OtpFailureReason =
  | "expired" // no active code (TTL elapsed) — caller should restart.
  | "mismatch" // code did not match; an attempt was consumed.
  | "locked" // maxAttempts reached for the active code; caller must restart.
  | "not_found"; // no OTP was ever started for this email (or already consumed).

export type VerifyOtpResult =
  | { ok: true; identity: VerifiedIdentity }
  | { ok: false; reason: OtpFailureReason };

/** Why a Google id_token verification failed (expected). */
export type GoogleFailureReason =
  | "malformed" // not a parseable/structurally-valid JWT.
  | "bad_signature" // signature did not verify against the JWKS.
  | "untrusted_issuer" // `iss` not in allowedIssuers.
  | "untrusted_audience" // `aud` not in allowedAudiences.
  | "expired" // `exp` in the past (or `nbf`/`iat` invalid) per injected Clock.
  | "email_unverified" // `email_verified` claim is not true.
  | "missing_email"; // no usable `email` claim present.

export type VerifyGoogleResult =
  | { ok: true; identity: VerifiedIdentity }
  | { ok: false; reason: GoogleFailureReason };

/**
 * Thrown ONLY for programmer/configuration faults the caller cannot recover from
 * at runtime (e.g. an OtpStore that rejects writes, a JwksSource that throws, an
 * empty allowedAudiences). Expected auth outcomes are NEVER thrown — they come
 * back in the discriminated unions above. `code` is a stable machine string.
 */
export class AuthKitError extends Error {
  readonly code:
    | "store_failure"
    | "jwks_failure"
    | "email_send_failure"
    | "config_invalid";
  constructor(
    code: AuthKitError["code"],
    message: string,
    /** Optional underlying cause (network error, adapter exception). */
    options?: { cause?: unknown },
  );
}

// ───────────────────────────────────────────────────────────────────────────
// 3. PORTS — the consumer injects an adapter for each. Adapters MAY be
//    CF-specific; the core never knows.
// ───────────────────────────────────────────────────────────────────────────

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
   * write), NOT a plain read-modify-write.
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

// ───────────────────────────────────────────────────────────────────────────
// 4. CONFIG types.
// ───────────────────────────────────────────────────────────────────────────

/** Email OTP tunables. All optional; defaults match the locked spec. */
export interface EmailOtpConfig {
  /** Digits in the code. Default 6. */
  length?: number;
  /** Code lifetime in seconds. Default 600 (10 minutes). */
  ttlSeconds?: number;
  /** Minimum seconds between sends to the same email. Default 60. */
  resendThrottleSeconds?: number;
  /** Verify attempts allowed per active code before lock. Default 5. */
  maxAttempts?: number;
}

/** The applied (no-undefined) Email OTP config, exported for callers that want the defaults. */
export const EMAIL_OTP_DEFAULTS: Required<EmailOtpConfig> = {
  length: 6,
  ttlSeconds: 600,
  resendThrottleSeconds: 60,
  maxAttempts: 5,
};

export interface GoogleVerifierConfig {
  /**
   * The OAuth client id(s) a valid id_token's `aud` must be one of. REQUIRED and
   * non-empty — an empty list throws AuthKitError("config_invalid") at
   * construction (a wildcard audience is never allowed).
   */
  allowedAudiences: string[];
  /**
   * Accepted `iss` values. Defaults to Google's two issuers:
   * ["https://accounts.google.com", "accounts.google.com"].
   */
  allowedIssuers?: string[];
}

export const GOOGLE_DEFAULT_ISSUERS: readonly string[] = [
  "https://accounts.google.com",
  "accounts.google.com",
];

// ───────────────────────────────────────────────────────────────────────────
// 5. ENGINE factories + their dependency bundles. These are the frozen entry points.
// ───────────────────────────────────────────────────────────────────────────

export interface EmailOtpDeps {
  store: OtpStore;
  sender: EmailSender;
  /** Defaults to a crypto.getRandomValues-backed generator if omitted. */
  codeGen?: CodeGenerator;
  /** Defaults to a Date.now()-backed clock if omitted. */
  clock?: Clock;
}

export interface EmailOtpService {
  /**
   * Begin/refresh an OTP for `email`. Normalizes the address, enforces the
   * resend throttle, generates+hashes+stores a fresh code, and sends it.
   * Returns "sent" with expiry, or "throttled" with retryAfter when a recent
   * code is still inside the throttle window. Throws AuthKitError only on a
   * store/sender failure.
   */
  startOtp(email: string): Promise<StartOtpResult>;
  /**
   * Verify `code` for `email`. On success returns the VerifiedIdentity and
   * consumes the record (single-use). On failure returns a typed reason; a
   * mismatch consumes an attempt and locks at maxAttempts. NEVER throws for an
   * expected failure.
   */
  verifyOtp(email: string, code: string): Promise<VerifyOtpResult>;
}

export function createEmailOtpService(
  deps: EmailOtpDeps,
  config?: EmailOtpConfig,
): EmailOtpService;

export interface GoogleVerifierDeps {
  jwks: JwksSource;
  /** Defaults to a Date.now()-backed clock if omitted. */
  clock?: Clock;
}

export interface GoogleVerifier {
  /**
   * Verify a GIS-issued id_token: parse, select signing key by `kid`, verify the
   * signature against the JWKS with `jose`, then check iss ∈ allowedIssuers,
   * aud ∈ allowedAudiences, exp/iat per Clock, and require email_verified.
   * Returns the VerifiedIdentity (providerSubject `google:<sub>`, normalized
   * email, displayName from `name`) or a typed reason. NEVER throws for an
   * expected verification failure; a JWKS adapter fault throws AuthKitError.
   */
  verify(idToken: string): Promise<VerifyGoogleResult>;
}

export function createGoogleVerifier(
  deps: GoogleVerifierDeps,
  config: GoogleVerifierConfig,
): GoogleVerifier;

// ───────────────────────────────────────────────────────────────────────────
// 6. Built-in helpers (re-exported defaults; not adapters to CF). Optional use.
// ───────────────────────────────────────────────────────────────────────────

/** WebCrypto-backed default CodeGenerator (uniform digits, no modulo bias). */
export const defaultCodeGenerator: CodeGenerator;
/** Date.now()-backed default Clock. */
export const systemClock: Clock;
/** Normalize an address the same way the core does (trim + lowercase). Exported so emo can match keys/users. */
export function normalizeEmail(raw: string): string;
