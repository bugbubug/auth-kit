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
export { AuthKitError } from "./types.js";
export { EMAIL_OTP_DEFAULTS, GOOGLE_DEFAULT_ISSUERS } from "./config.js";
export { createEmailOtpService } from "./email-otp.js";
export { createGoogleVerifier } from "./google.js";
// ── Built-in helpers (re-exported defaults; optional use) ────────────────────
export { defaultCodeGenerator } from "./crypto.js";
export { systemClock, normalizeEmail } from "./util.js";
//# sourceMappingURL=index.js.map