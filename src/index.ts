/**
 * @bugbubug/auth-kit — FROZEN PUBLIC BARREL (v1).
 *
 * This file IS the frozen contract surface; the authoritative baseline is the
 * api-extractor report etc/auth-kit.api.md (run `bun run api:check`). Changes
 * here are additive-only. Pure, framework/runtime-agnostic: no Hono / Workers /
 * Node imports. Two methods only — Email OTP and Google id_token verification —
 * each returning a single VerifiedIdentity. The SDK ONLY verifies control of an
 * identifier; it never decides users/sessions, never sets cookies, never stores
 * user rows. Account-linking POLICY stays in the consumer.
 *
 * zod is NOT imported here (the core is zod-free). The optional input-parsing
 * helpers live in the separate, non-frozen `@bugbubug/auth-kit/zod` subpath.
 */

// ── Result + error types ────────────────────────────────────────────────────
export type {
  VerifiedIdentity,
  StartOtpResult,
  OtpFailureReason,
  VerifyOtpResult,
  GoogleFailureReason,
  VerifyGoogleResult,
} from "./types.js";
export { AuthKitError } from "./types.js";

// ── Ports (the consumer injects an adapter for each) ─────────────────────────
export type {
  Clock,
  CodeGenerator,
  OtpRecord,
  OtpStore,
  OtpEmail,
  EmailSender,
  Jwk,
  JwksSource,
} from "./ports.js";

// ── Config types + applied defaults ──────────────────────────────────────────
export type { EmailOtpConfig, GoogleVerifierConfig } from "./config.js";
export { EMAIL_OTP_DEFAULTS, GOOGLE_DEFAULT_ISSUERS } from "./config.js";

// ── Engine factories + their dependency/service interfaces ───────────────────
// (./email-otp and ./google are implemented in the next phase; the frozen
//  contract mandates these exact named exports flow through the barrel.)
export type {
  EmailOtpDeps,
  EmailOtpService,
} from "./email-otp.js";
export { createEmailOtpService } from "./email-otp.js";

export type {
  GoogleVerifierDeps,
  GoogleVerifier,
} from "./google.js";
export { createGoogleVerifier } from "./google.js";

// ── Built-in helpers (re-exported defaults; optional use) ────────────────────
export { defaultCodeGenerator } from "./crypto.js";
export { systemClock, normalizeEmail } from "./util.js";

// ── Password hashing PRIMITIVES (pure PBKDF2-HMAC-SHA256; storage stays in the
//    consumer — the kit never owns the users row, same boundary as OTP/Google) ─
export type { PasswordHashConfig } from "./crypto.js";
export {
  hashPassword,
  verifyPassword,
  PASSWORD_HASH_DEFAULTS,
} from "./crypto.js";
