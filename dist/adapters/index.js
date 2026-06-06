/**
 * Optional, framework/runtime-agnostic ADAPTERS for the auth-kit ports.
 *
 * These are dev/test-grade and pure-standard-library: backed by `Map`, `fetch`,
 * and `globalThis.crypto` only — NO Workers/CF/Hono/Node imports. They are NOT
 * part of the frozen core contract; the core never imports this barrel. CF-native
 * adapters (KV-backed OtpStore, `send_email` binding EmailSender) live in the
 * consumer. Only FetchJwksSource performs real network egress, and only when
 * verifying Google id_tokens for real.
 */
export { InMemoryOtpStore } from "./memory-otp-store.js";
export { NoopEmailSender, RecordingEmailSender } from "./noop-email-sender.js";
export { StaticJwksSource } from "./static-jwks.js";
export { FetchJwksSource } from "./jwks-fetch.js";
//# sourceMappingURL=index.js.map