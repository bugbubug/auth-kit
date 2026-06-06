/**
 * OPTIONAL input-parsing helpers for @bugbubug/auth-kit (the `@bugbubug/auth-kit/zod`
 * subpath). This module — and ONLY this module — imports zod, which is an OPTIONAL
 * peerDependency pinned to the same range emo uses ("^3.24.1"). The frozen core is
 * zod-free and never imports this file, so a consumer on a different zod minor (or
 * none at all) is never broken by the engine. Import this subpath only if you want
 * ready-made schemas to validate the raw request bodies before calling the engine.
 *
 * The schemas mirror the engine's method inputs exactly:
 *   • startOtp(email)            ← emailStartInput
 *   • verifyOtp(email, code)     ← otpVerifyInput
 *   • verify(idToken)            ← googleVerifyInput
 *
 * They intentionally do NOT normalize (trim/lowercase) — the core owns email
 * normalization via `normalizeEmail`, so these stay pure shape/format guards.
 */
import { z } from "zod";
/** Body for starting an Email OTP: `{ email }`. */
export const emailStartInput = z.object({
    email: z.string().email(),
});
/** Body for verifying an Email OTP: `{ email, code }`. */
export const otpVerifyInput = z.object({
    email: z.string().email(),
    code: z.string(),
});
/** Body for verifying a Google id_token: `{ idToken }`. */
export const googleVerifyInput = z.object({
    idToken: z.string().min(1),
});
//# sourceMappingURL=zod.js.map