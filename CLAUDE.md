# CLAUDE.md — @bugbubug/auth-kit

Agent index for this repo. Read this first; it points at the contract and the
hard rules, it does not restate the whole API (that's `docs/API.md`).

The SDK's **own** toolchain is **bun** (`bun install` / `bun test` /
`bun run build` / `bun run typecheck` / `bun run lint` / `bun run api:check`).
The **consumer-facing** install line stays **pnpm** (`pnpm add github:...#tag`) —
emo/habibi are pnpm workspaces.

## What this is

A **pure, hexagonal auth-VERIFICATION library**. It proves a caller controls an
identifier and returns a single `VerifiedIdentity`. **Two flows:** Email OTP and
OIDC `id_token` verification (since v1.2 a generic, config-parameterized engine —
`createOidcVerifier` — with Google shipping as the built-in preset).

It is **not** a service and does **not** own users/sessions/cookies/account-linking.
It runs **in-process** in the consumer's Worker. The consumer (emo) owns identity,
the unique index, the session cookie, and register-vs-login policy. The kit's job
ends at `VerifiedIdentity`.

**v1.1.0 (additive):** added pure password-hashing **PRIMITIVES** —
`hashPassword` / `verifyPassword` (PBKDF2-HMAC-SHA256, self-describing
`pbkdf2-sha256$<iters>$<saltHex>$<hashHex>`) + `PASSWORD_HASH_DEFAULTS` /
`PasswordHashConfig`, in `src/crypto.ts`. Same "verify only" boundary: the kit
hashes/verifies a password but **storage + orchestration** (the users row,
register/login/reset flow, throttling) stay in the consumer. Pure WebCrypto, no
new deps.

**v1.1.1 (fix):** `PASSWORD_HASH_DEFAULTS.iterations` lowered **600000 → 100000**.
Cloudflare Workers' WebCrypto hard-caps PBKDF2 at 100000 — `crypto.subtle.deriveBits`
throws `NotSupportedError: iteration counts above 100000 are not supported` above it,
so the old 600000 default made `hashPassword` **fatal on workerd** (it threw at
runtime; the bun/Node test suite never caught it). 100000 is the highest portable
value that runs unchanged on Workers/Node/bun. Surface unchanged (value-only); old
hashes still verify (the count is parsed from the stored string), and a Node-only
consumer can still pass `{ iterations: 600_000 }` explicitly.

**v1.2.0-dev (UNRELEASED — committed after v1.1.1, not yet tagged; all
ADDITIVE, every pre-existing test passes unchanged):**

1. **Generic OIDC verifier extracted** — `src/oidc.ts` `createOidcVerifier(deps,
   config)` (+ `OidcVerifierDeps`/`OidcVerifier` there, `OidcVerifierConfig` +
   `validateOidcConfig` in `src/config.ts`, additive aliases
   `OidcFailureReason = GoogleFailureReason` / `VerifyOidcResult =
   VerifyGoogleResult` in `src/types.ts`). The whole verification pipeline moved
   there verbatim, parameterized by `allowedIssuers` (required — no generic
   default) / `allowedAudiences` / `subjectPrefix` (→ `<prefix>:<sub>`) /
   `algorithms` (default `["RS256"]`) / `requireEmailVerified` (default true) /
   `displayNameClaim` (default `"name"`). `createGoogleVerifier` is now a THIN
   PRESET: `validateGoogleConfig` (Google issuer defaulting + exact error
   messages) then delegate with `subjectPrefix: "google"` — behavior
   byte-compatible. Adding Apple/Microsoft login is now just another config.
2. **`VerifiedIdentity.provider?: string`** (additive optional) — the method
   discriminant (`"email"` / `"google"` / the OIDC `subjectPrefix`), matching
   the `providerSubject` prefix so consumers stop parsing it. Optional in the
   frozen type, but ALWAYS populated by the engines from v1.2.
3. **`FetchJwksOptions.timeoutMs?: number`** (default 5000) — the
   whole-operation JWKS abort deadline is now configurable; a
   non-positive/non-integer value throws `AuthKitError("config_invalid")` at
   construction.

## Layout (hexagonal)

```
src/
  index.ts          FROZEN public barrel — IS the contract surface (frozen baseline: etc/auth-kit.api.md)
  types.ts          VerifiedIdentity (+ v1.2 provider?), result/reason unions (+ v1.2 Oidc aliases), AuthKitError (no logic)
  ports.ts          port interfaces: OtpStore/OtpRecord, EmailSender/OtpEmail, JwksSource/Jwk, Clock, CodeGenerator
  config.ts         EmailOtpConfig/GoogleVerifierConfig/OidcVerifierConfig, defaults, validators
                    (applyEmailDefaults/validateGoogleConfig/validateOidcConfig)
  email-otp.ts      createEmailOtpService — deterministic OTP flow
  oidc.ts           v1.2 createOidcVerifier — the generic engine: parse + jose verify + claim checks + projection
  google.ts         createGoogleVerifier — THIN PRESET over oidc.ts (Google issuers + subjectPrefix "google")
  crypto.ts         sha256Hex, constant-time compare, defaultCodeGenerator (WebCrypto)
  util.ts           normalizeEmail (exported, frozen), systemClock, otpKey
  zod.ts            OPTIONAL non-frozen "@bugbubug/auth-kit/zod" subpath (imports zod peer)
  adapters/         OPTIONAL GENERIC adapters: FetchJwksSource (v1.2: configurable timeoutMs),
                    StaticJwksSource, InMemoryOtpStore, NoopEmailSender, RecordingEmailSender
test/               bun test: email-otp, google (real keypair via jose), oidc (custom provider),
                    jwks-fetch (timeout), password, contract seam;
                    zod-mirror.type-test.ts (typecheck-only drift guard, not a runtime test)
etc/                auth-kit.api.md — AUTHORITATIVE frozen surface (api-extractor report)
docs/               BUILD_PLAN.md, OPEN_RISKS.md, API.md
eslint.config.js    import-boundary enforcement (no zod/node:*/hono/workers-types in src/**)
api-extractor.json  config for the frozen-surface report (etc/auth-kit.api.md)
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

`src/index.ts` **is** the public surface. The **authoritative frozen baseline** is
`etc/auth-kit.api.md`, generated from `dist/index.d.ts` by
[@microsoft/api-extractor](https://api-extractor.com/) (it replaced the old
hand-mirrored `docs/FROZEN_CONTRACT.ts`). `bun run api:check` fails CI if the
current `.d.ts` drifts from that report; regenerate it deliberately with
`bun run api:update` after an **additive** change.

Changes are **additive-only**: new optional fields / new exports are fine; renaming,
removing, retyping, or making a field required is breaking. Consumers pin by
immutable git tag, so any change ships as a new tag (never force-move a tag).

> Strict order when the surface legitimately grows: edit `src` →
> `bun run build` (regenerates `dist/index.d.ts`) → `bun run api:update` (re-reads
> the fresh `.d.ts`). Running `api:update` against a stale `dist/` would freeze a
> wrong baseline.

**`exactOptionalPropertyTypes` trap:** under this strict flag, widening an optional
frozen field from `displayName?: string` to `displayName?: string | undefined` is a
**retype = breaking change**. When an optional value may be absent, **omit the key**
at the construction site instead of assigning `undefined` (see `google.ts` building
`VerifiedIdentity`). Never relax a frozen interface to satisfy the compiler.

### types.ts ↔ zod.ts drift guard

`test/zod-mirror.type-test.ts` is a **typecheck-only** file (emits no runtime code,
both imports are `import type`, so zod never enters the runtime graph). It pins each
`@bugbubug/auth-kit/zod` schema's inferred type against the engine **method-input**
shape it mirrors — `emailStartInput`↔`{email}`, `otpVerifyInput`↔`{email,code}`,
`googleVerifyInput`↔`{idToken}` — via a compile-time `Equals<A,B>`. If a schema
gains/loses/retypes a field, `bun run typecheck` FAILS.

> Caveat (intentionally weaker than llm-kit's guard): auth-kit has **no
> zod-shadowed IR types** in `src/types.ts`, so there is no `z.infer EQUALS
> frozen-IR-type` assertion to make. The /zod schemas mirror method inputs, so the
> guard pins those literal shapes instead.

## Hard rules (do not violate)

1. **No Workers / Hono / Node imports in the core.** Pure WebCrypto + `jose`
   only, so it runs in Workers, Node 24, and bun unchanged. This **portability**
   rule applies to `node:*` / `hono` / `@cloudflare/workers-types` (runtime- or
   bundler-specific) — **not** to zod (zod is pure JS and runs everywhere; it is
   kept off the core graph for the different reasons in rule #7). The import-graph
   ban is now enforced by **ESLint** (`eslint.config.js`, `no-restricted-imports`
   under `src/**`, exempting `src/adapters/**` + `src/zod.ts`) — a cheap,
   CI-decidable proxy for "minimal third-party runtime import graph". `jose` is an
   allowed runtime dep (used only in `src/oidc.ts` — the generic engine
   `src/google.ts` is a preset of since v1.2). Run `bun run lint`.
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
   `RecordingEmailSender` → zero egress. `FetchJwksSource` arms an
   `AbortController` timeout (`timeoutMs`, default 5000 — configurable since
   v1.2) that stays armed across **both** the `fetch` and the response-body read
   (v1.0.2/v1.0.3), so a stalled JWKS endpoint can't hang the verify path; it
   still raises the three distinct `jwks_failure` messages (network / non-2xx /
   invalid-JSON).
6. **Google/OIDC verify goes through the `JwksSource` PORT** — fetch keys, then verify
   with `jose`'s low-level API. **Never** `jose.createRemoteJWKSet` (that would
   make the core fetch the network directly and bypass the port / the zero-egress
   guarantee).
7. **`zod` is an optional peer**, pinned `^3.24.1`, used only in the non-frozen
   off-barrel `/zod` subpath; the frozen core never imports it. The reason is
   **not** purity/portability (zod is pure JS — it runs unchanged on
   workerd/Node/bun). The real reasons:
   - **opt-in / zero-bytes-by-default + zero skew** — zod is reached only via the
     `@bugbubug/auth-kit/zod` off-barrel subpath, so a consumer who doesn't import
     it ships zero zod bytes in their bundled Worker, and the engine never resolves
     the consumer's zod version (no version-skew breakage in core);
   - **no validator types in the frozen `.d.ts`** — the frozen `dist/index.d.ts`
     leaks no zod/schema types, keeping the surface pure data types;
   - **lenient wire handling** — the verifiers return typed reason unions and never
     `.parse()`; a strict schema at the core boundary would regress that leniency
     and collapse the distinct typed reasons;
   - **v3 surface for consumer type-identity** — the `/zod` IR mirror stays on the
     zod v3 surface so a consumer pinned to v3 (emo) keeps schema type-identity.
8. **On email-send failure, LEAVE the stored (hashed) OTP in place** — it
   self-evicts via the native store TTL — and surface
   `AuthKitError("email_send_failure")`. Do **NOT** delete/consume the record on
   the send-failure path (tried in v1.0.2, **reverted in v1.0.3**): `sender.send`
   is not atomic, so the email may already be delivered when `send()` rejects, and
   a blind keyed delete would (a) make a delivered code permanently unverifiable,
   (b) clobber a concurrent `startOtp`'s record (consume is a keyed delete, not
   compare-and-delete), and (c) drop the resend-throttle state, enabling
   un-throttled retries.

## How a consumer wires it

The consumer installs by **git tag** (`pnpm add github:bugbubug/auth-kit#v1.0.4`)
and consumes the committed **`dist/` (ESM `.js` + `.d.ts`)** — its `tsc` reads the
shipped `.d.ts` (so the kit's tsconfig strictness never leaks into the consumer's
typecheck), its bundler (wrangler/esbuild) bundles the `.js`. Rebuild `dist` with
the kit's own toolchain — `bun run build` — before tagging a release. `jose` rides
along as the kit's transitive dep. The consumer
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

## Test / gate commands (the SDK's own toolchain — bun)

```bash
bun install         # produces/uses bun.lock (committed); reads bunfig.toml (linker=isolated)
bun test            # OTP flow + Google verify (real jose keypair) + contract seam, zero egress
bun run typecheck   # tsc --noEmit against the strict config (also typechecks the zod-mirror drift guard)
bun run lint        # eslint . — import-boundary enforcement
bun run api:check   # api-extractor — fails if dist/index.d.ts drifts from etc/auth-kit.api.md
bun run build       # tsc -p tsconfig.build.json — regenerates dist/ (.js + .d.ts) before tagging/api:update
```

`bunfig.toml` sets `[install] linker = "isolated"` (pnpm-style nested deps) so
api-extractor's `ajv-draft-04` resolves its own `ajv@8` instead of colliding with
eslint's `ajv@6` under bun's default hoisted layout — required for `api:check`.

> The `pnpm add github:...#tag` install line above is **consumer-facing** (emo is a
> pnpm workspace); only the SDK's **own** dev/test/build is bun.
