# CLAUDE.md — @bugbubug/auth-kit

Agent index for this repo. Read this first; it points at the contract and the
hard rules, it does not restate the whole API (that's `docs/API.md`).

## What this is

A **pure, hexagonal auth-VERIFICATION library**. It proves a caller controls an
identifier and returns a single `VerifiedIdentity`. **Two methods only:** Email
OTP and Google `id_token` verification.

It is **not** a service and does **not** own users/sessions/cookies/account-linking.
It runs **in-process** in the consumer's Worker. The consumer (emo) owns identity,
the unique index, the session cookie, and register-vs-login policy. The kit's job
ends at `VerifiedIdentity`.

## Layout (hexagonal)

```
src/
  index.ts          FROZEN public barrel — IS the contract surface (== docs/FROZEN_CONTRACT.ts)
  types.ts          VerifiedIdentity, result/reason unions, AuthKitError (no logic)
  ports.ts          port interfaces: OtpStore/OtpRecord, EmailSender/OtpEmail, JwksSource/Jwk, Clock, CodeGenerator
  config.ts         EmailOtpConfig/GoogleVerifierConfig, defaults, validators (applyEmailDefaults/validateGoogleConfig)
  email-otp.ts      createEmailOtpService — deterministic OTP flow
  google.ts         createGoogleVerifier — parse + jose verify + claim checks
  crypto.ts         sha256Hex, constant-time compare, defaultCodeGenerator (WebCrypto)
  util.ts           normalizeEmail (exported, frozen), systemClock, otpKey
  zod.ts            OPTIONAL non-frozen "@bugbubug/auth-kit/zod" subpath (imports zod peer)
  adapters/         OPTIONAL GENERIC adapters: FetchJwksSource, StaticJwksSource,
                    InMemoryOtpStore, NoopEmailSender, RecordingEmailSender
test/               vitest: email-otp, google (real keypair via jose), contract seam
docs/               FROZEN_CONTRACT.ts (authoritative), BUILD_PLAN.md, OPEN_RISKS.md, API.md
```

- **`src/` core is framework-agnostic** — the deterministic flow, no runtime
  knowledge.
- **`src/adapters/` are OPTIONAL generic adapters** (in-memory, static, fetch)
  for the non-CF cases and for tests.
- **CF/Workers adapters live in the CONSUMER, not here.** `KvOtpStore` (over a KV
  namespace) and `CfEmailSender` (over the `send_email` binding) are written in
  emo's `apps/api/src/auth/adapters.ts`, because they import CF bindings the core
  must never touch.

## The frozen contract

`src/index.ts` **is** the public surface and **must equal** `docs/FROZEN_CONTRACT.ts`.
Changes are **additive-only**: new optional fields / new exports are fine; renaming,
removing, retyping, or making a field required is breaking. Consumers pin by
immutable git tag, so any change ships as a new tag (never force-move a tag).

## Hard rules (do not violate)

1. **No Workers / Hono / Node imports in the core.** Pure WebCrypto + `jose`
   only, so it runs in Workers, vitest-pool-workers, and Node 24 unchanged.
2. **Expected outcomes are discriminated unions, NOT throws.** `StartOtpResult`,
   `VerifyOtpResult`, `VerifyGoogleResult` carry every caller-recoverable outcome
   (`sent`/`throttled`, `expired`/`mismatch`/`locked`/`not_found`, the Google
   reasons). The factories never throw for a normal auth failure.
3. **`AuthKitError` is for adapter/config faults ONLY** — `store_failure`,
   `jwks_failure`, `email_send_failure`, `config_invalid`. A store that rejects
   writes, a JWKS adapter that throws, an empty `allowedAudiences`. Never for an
   expected auth result.
4. **OTP codes are stored sha-256 HASHED** (`OtpRecord.codeHash`, lowercase hex),
   never plaintext, and compared **constant-time**. A store breach must not leak
   live codes.
5. **Egress ONLY via `FetchJwksSource` + a real `EmailSender`.** The core makes
   no network calls. Dev/test inject `StaticJwksSource` + `NoopEmailSender`/
   `RecordingEmailSender` → zero egress.
6. **Google verify goes through the `JwksSource` PORT** — fetch keys, then verify
   with `jose`'s low-level API. **Never** `jose.createRemoteJWKSet` (that would
   make the core fetch the network directly and bypass the port / the zero-egress
   guarantee).
7. **`zod` is an optional peer**, pinned `^3.24.1` to match emo, used only in the
   non-frozen `/zod` subpath. The frozen core never imports it, so a consumer's
   zod minor skew can't break the engine.

## How a consumer wires it

The consumer installs by **git tag** (`pnpm add github:bugbubug/auth-kit#v1.0.1`)
and consumes the committed **`dist/` (ESM `.js` + `.d.ts`)** — its `tsc` reads the
shipped `.d.ts` (so the kit's tsconfig strictness never leaks into the consumer's
typecheck), its bundler (wrangler/esbuild) bundles the `.js`. Rebuild `dist` with
`pnpm build` before tagging a release. `jose` rides along as the kit's transitive dep. The consumer
writes the CF adapters (`KvOtpStore`, `CfEmailSender`), re-uses `FetchJwksSource`,
calls `createEmailOtpService` / `createGoogleVerifier`, and maps the result onto
its own identity layer:

```ts
// VerifiedIdentity -> emo IdentityResult (the one-line glue, used by both providers)
function toIdentityResult(id: VerifiedIdentity): IdentityResult {
  return {
    providerSubject: id.providerSubject,          // "email:<addr>" | "google:<sub>"
    profile: { email: id.email, displayName: id.displayName },
  };
}
```

- `providerSubject` already carries the `email:` / `google:` prefix, so it slots
  straight into emo's `(productId, provider, providerSubject)` unique index.
- `email` is already normalized (trim + lowercase) — use `normalizeEmail` if you
  need to match keys/rows yourself.
- `emailVerified` is always `true` on success; emo drops it at the seam (read it
  *before* mapping if account-linking policy needs it).
- `displayName` is present for Google (`name` claim), absent for Email OTP.

## Test commands

```bash
pnpm test        # vitest: OTP flow + Google verify (real jose keypair) + contract seam, zero egress
pnpm typecheck   # tsc --noEmit against the strict config
```
