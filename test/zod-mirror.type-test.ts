/**
 * COMPILE-TIME drift guard for the optional `@bugbubug/auth-kit/zod` schemas.
 *
 * This file emits NO runtime code and ships nothing — it exists purely so
 * `tsc --noEmit` (tsconfig `include` covers "test") fails if a /zod schema's
 * inferred type drifts from the engine method-input shape it documents itself as
 * mirroring. Both imports are TYPE-ONLY, so this never enters the runtime/bundle
 * graph and never pulls zod into the core import graph (the ESLint boundary rule
 * exempts type-only positions anyway; here we use `import type` explicitly).
 *
 * AUTH-KIT CAVEAT (weaker than llm-kit's guard): unlike llm-kit, auth-kit has NO
 * zod-shadowed IR types in src/types.ts — the /zod schemas mirror the ENGINE
 * METHOD INPUTS, not any exported core type:
 *   • emailStartInput   ↔ startOtp(email)         → { email: string }
 *   • otpVerifyInput    ↔ verifyOtp(email, code)  → { email: string; code: string }
 *   • googleVerifyInput ↔ verify(idToken)         → { idToken: string }
 * So there is no `z.infer EQUALS frozen-IR-type` counterpart to assert. Instead we
 * pin each inferred shape against the documented method-input literal. If a schema
 * gains/loses/retypes a field (drifting from the method signature the engine
 * exposes), one of the `Equals<...>` checks below stops resolving to `true` and
 * typecheck FAILS.
 */

import type { z } from "zod";
import type {
  emailStartInput,
  otpVerifyInput,
  googleVerifyInput,
} from "../src/zod.js";

/**
 * Exact compile-time type equality (invariant in both directions). Resolves to
 * `true` only when A and B are mutually assignable AND identical — a one-sided
 * `extends` would miss an extra/missing field, so this uses the standard
 * function-identity trick for a true bidirectional equality.
 */
type Equals<A, B> =
  (<T>() => T extends A ? 1 : 2) extends (<T>() => T extends B ? 1 : 2)
    ? true
    : false;

// ── The documented engine method-input shapes the /zod schemas mirror ────────

// startOtp(email) — emailStartInput parses `{ email }`.
const _emailStart: Equals<z.infer<typeof emailStartInput>, { email: string }> =
  true;
void _emailStart;

// verifyOtp(email, code) — otpVerifyInput parses `{ email, code }`.
const _otpVerify: Equals<
  z.infer<typeof otpVerifyInput>,
  { email: string; code: string }
> = true;
void _otpVerify;

// verify(idToken) — googleVerifyInput parses `{ idToken }`.
const _googleVerify: Equals<
  z.infer<typeof googleVerifyInput>,
  { idToken: string }
> = true;
void _googleVerify;
