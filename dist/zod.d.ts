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
export declare const emailStartInput: z.ZodObject<{
    email: z.ZodString;
}, "strip", z.ZodTypeAny, {
    email: string;
}, {
    email: string;
}>;
export type EmailStartInput = z.infer<typeof emailStartInput>;
/** Body for verifying an Email OTP: `{ email, code }`. */
export declare const otpVerifyInput: z.ZodObject<{
    email: z.ZodString;
    code: z.ZodString;
}, "strip", z.ZodTypeAny, {
    code: string;
    email: string;
}, {
    code: string;
    email: string;
}>;
export type OtpVerifyInput = z.infer<typeof otpVerifyInput>;
/** Body for verifying a Google id_token: `{ idToken }`. */
export declare const googleVerifyInput: z.ZodObject<{
    idToken: z.ZodString;
}, "strip", z.ZodTypeAny, {
    idToken: string;
}, {
    idToken: string;
}>;
export type GoogleVerifyInput = z.infer<typeof googleVerifyInput>;
//# sourceMappingURL=zod.d.ts.map