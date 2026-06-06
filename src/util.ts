/**
 * Shared, dependency-free utilities. `normalizeEmail` is part of the frozen
 * public surface (exported so emo matches keys/users the same way the core does).
 */

import type { Clock } from "./ports.js";

/**
 * Normalize an address the same way the core does: trim surrounding whitespace,
 * then lowercase. This is the canonical form used both for the `email:<addr>`
 * providerSubject and for the OtpStore key, so emo can derive matching keys/rows.
 */
export function normalizeEmail(raw: string): string {
  return raw.trim().toLowerCase();
}

/**
 * Date.now()-backed default Clock. Returns the current time in Unix epoch
 * MILLISECONDS from the platform clock. Inject a fixed Clock in tests for
 * determinism.
 */
export const systemClock: Clock = {
  now(): number {
    return Date.now();
  },
};

/**
 * Derive the OtpStore key for an email. The core owns key derivation so adapters
 * never build keys themselves; the `otp:` prefix namespaces OTP records inside a
 * shared KV/store and the email is normalized first for stable lookups.
 */
export function otpKey(email: string): string {
  return "otp:" + normalizeEmail(email);
}
