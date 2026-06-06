# Build plan — @bugbubug/auth-kit (v1)

Authoritative public API surface: `docs/FROZEN_CONTRACT.ts`.

## SDK file plan

| path | purpose |
| --- | --- |
| `package.json` | Package manifest: name @bugbubug/auth-kit, version 1.0.0, type module, exports map ('.' -> src/index.ts raw TS, './adapters' -> generic adapters, './zod' -> optional zod helpers). deps: jose (^6). peerDependenciesMeta: zod optional, pinned to ^3.24.1 to match emo. No build script required (ship raw TS); provide a `types` build via tsc for IDEs. devDeps: typescript, vitest. |
| `tsconfig.json` | Strict TS config (target ES2022, module ESNext, moduleResolution Bundler, lib WebWorker+ES2022, declaration true, declarationDir ./dist/types, noEmit false for the types build). No DOM-only / Node-only libs in core. |
| `.gitignore` | Ignore node_modules, dist, coverage, *.log, .dev.vars. |
| `LICENSE` | MIT license (bugbubug). |
| `src/index.ts` | FROZEN public barrel. Re-exports VerifiedIdentity, all result/reason unions, AuthKitError, the ports (OtpStore/EmailSender/JwksSource/Clock/CodeGenerator + OtpRecord/OtpEmail/Jwk), config types + EMAIL_OTP_DEFAULTS + GOOGLE_DEFAULT_ISSUERS, the two factories (createEmailOtpService/createGoogleVerifier) and their *Deps/*Service interfaces, and the built-in helpers (defaultCodeGenerator, systemClock, normalizeEmail). This is the verbatim frozen contract. |
| `src/types.ts` | VerifiedIdentity, the discriminated result unions (StartOtpResult, VerifyOtpResult, OtpFailureReason, VerifyGoogleResult, GoogleFailureReason), and AuthKitError. No logic. |
| `src/ports.ts` | Port interfaces: OtpStore, OtpRecord, EmailSender, OtpEmail, JwksSource, Jwk, Clock, CodeGenerator. No implementations. |
| `src/config.ts` | EmailOtpConfig, GoogleVerifierConfig, EMAIL_OTP_DEFAULTS, GOOGLE_DEFAULT_ISSUERS, and an applyDefaults helper. Throws AuthKitError('config_invalid') on empty allowedAudiences / non-positive numbers. |
| `src/email-otp.ts` | createEmailOtpService: deterministic flow — normalizeEmail -> key 'otp:<email>' -> startOtp (throttle check via issuedAt+resendThrottle, generate digits, sha-256 hash, store with TTL, sender.send) and verifyOtp (get; null->not_found; expired->expired+consume; compare hash; mismatch->incrementAttempts, lock at maxAttempts->consume+locked; match->consume+VerifiedIdentity providerSubject 'email:<email>', emailVerified true). All expected outcomes via unions; store/sender faults -> AuthKitError. |
| `src/google.ts` | createGoogleVerifier: parse header for kid, jwks.getKeys(), import key via jose, jwtVerify with issuer/audience options, then assert email_verified true and email present; build VerifiedIdentity providerSubject 'google:<sub>', normalized email, displayName from name. Map jose/validation failures to the typed GoogleFailureReason union; JWKS adapter throw -> AuthKitError('jwks_failure'). |
| `src/crypto.ts` | WebCrypto helpers: sha256Hex(string) and a constant-time hex compare used by verifyOtp; defaultCodeGenerator (uniform digits via crypto.getRandomValues, rejection sampling, no modulo bias). Pure WebCrypto so it runs in Workers + vitest-pool-workers + Node 24. |
| `src/util.ts` | normalizeEmail (trim+lowercase), systemClock, and key derivation. Exported normalizeEmail so consumers match keys/users. |
| `src/zod.ts` | OPTIONAL non-frozen subpath ('@bugbubug/auth-kit/zod'): zod schemas mirroring startOtp/verify inputs for consumers who want runtime validation. Imports zod (peer). Core never imports this file, so a zod version skew can't break the engine. |
| `src/adapters/jwks-fetch.ts` | FetchJwksSource: fetches Google certs (https://www.googleapis.com/oauth2/v3/certs), caches by Cache-Control max-age via injected Clock. The ONLY real-egress code path; not used by tests. |
| `src/adapters/static-jwks.ts` | StaticJwksSource(keys): returns an injected key set, zero egress — for tests and for consumers that pin keys. |
| `src/adapters/memory-otp-store.ts` | InMemoryOtpStore: Map-backed OtpStore with manual TTL via Clock — for tests / dev, zero persistence. |
| `src/adapters/noop-email-sender.ts` | NoopEmailSender (and RecordingEmailSender): no egress; records sent OtpEmail for tests/dev. Lets dev verify a code without sending mail. |
| `test/email-otp.test.ts` | Vitest: full OTP flow — sent/throttled, expiry, mismatch attempt counting, lock at maxAttempts, success+consume single-use, hash-not-plaintext invariant, normalization. Uses InMemoryOtpStore + RecordingEmailSender + fixed Clock/CodeGenerator. Zero egress. |
| `test/google.test.ts` | Vitest: generate an RSA keypair (jose), sign a test id_token, verify happy path + each GoogleFailureReason (bad aud/iss, expired, email_unverified, missing_email, bad signature, malformed) via StaticJwksSource. Zero egress. |
| `test/contract.test.ts` | Type-level + runtime assertion that VerifiedIdentity maps onto emo's IdentityResult shape (providerSubject/email/displayName), guarding the frozen seam. |
| `README.md` | What it is (pure hexagonal auth verification lib, in-process, no service), the two methods, the ports, a CF-Worker wiring example (KV OtpStore + send_email EmailSender + fetch JwksSource) and a test wiring example (in-memory + static), the zero-egress guarantee, and the git-tag install line. |
| `CLAUDE.md` | Agent index: hexagonal layout (core = framework-agnostic flow, adapters/ = optional CF/test impls), the FROZEN contract lives in src/index.ts (additive-only), hard rules (no Hono/Workers import in core; expected outcomes are unions not throws; codes stored hashed; egress only in fetch-jwks + real EmailSender), how emo consumes it (git-tag, raw TS), and the VerifiedIdentity->IdentityResult mapping. |
| `docs/API.md` | The frozen public API reference: every exported type/function with semantics, defaults table (length 6 / ttl 600 / resend 60 / maxAttempts 5), the result/reason unions enumerated, and the emo IdentityResult mapping. The downstream build agents consume this verbatim. |

## Finalization decisions

> Note: the orchestration template left the verbatim "Finalization decisions" text unsubstituted (`undefined`). The decisions below are reproduced verbatim from the frozen-spec JSON fields that record the finalized engineering choices (`zodVersion`, `emoIntegrationSpec`, `hardRulesToHonor`, `emoChangePlan`).

### zod version (locked)

Pinned to: `^3.24.1` (matches emo; SDK core is zod-free, zod is an optional peer used only in the `@bugbubug/auth-kit/zod` subpath).

### emo integration spec (verbatim)

```text
GOAL: turn emo's two placeholder providers into THIN adapters over @bugbubug/auth-kit, add an additive two-step email-start endpoint, wire Google id_token verification, and keep dev/test zero-egress. The engine owns the flow; emo owns users/sessions/cookies (unchanged) and account-linking policy.

== Dependency ==
Add to apps/api/package.json dependencies: "@bugbubug/auth-kit": "github:bugbubug/auth-kit#v1.0.0" (git-tag pin, raw TS source compiled by wrangler's esbuild). Because the SDK ships raw TS, no build step is needed; `jose` is a transitive dep of the SDK (added to the SDK's package.json, NOT emo's). Run `pnpm add -F @app/api github:bugbubug/auth-kit#v1.0.0`. zod stays at emo's ^3.24.1 (SDK matches; SDK core is zod-free so no version pressure).

== ADAPTERS map onto VerifiedIdentity -> IdentityResult (near-zero glue) ==
emo's IdentityResult = { providerSubject, profile: { email?, displayName? } }. The SDK's VerifiedIdentity = { providerSubject, email, emailVerified, displayName? }. The one-line mapping (used by BOTH providers):
  function toIdentityResult(id: VerifiedIdentity): IdentityResult {
    return { providerSubject: id.providerSubject, profile: { email: id.email, displayName: id.displayName } };
  }
providerSubject already carries the `email:`/`google:` prefix so it slots straight into the (productId, provider, providerSubject) unique index. emailVerified is dropped at this seam (always true on success) — if emo later wants account-linking policy it can read it before mapping.

== EmailIdentityProvider becomes a thin adapter ==
File apps/api/src/auth/identity.ts. The `email` flow is TWO STEPS and the OTP send happens at the new /start endpoint, NOT inside authenticate(). So EmailIdentityProvider.authenticate ONLY VERIFIES the code (the second leg of the existing POST /api/auth/login path). Change EmailIdentityProvider to take an EmailOtpService and verify:
  constructor(private readonly otp: EmailOtpService | null) {}
  async authenticate(ctx) {
    if (!this.otp) throw new NotImplementedError("email");   // keeps the loud 501 when sender unconfigured
    const c = ctx.credentials as { email?: unknown; code?: unknown };
    const email = typeof c?.email === "string" ? c.email : "";
    const code  = typeof c?.code  === "string" ? c.code  : "";
    if (!email || !code) throw new InvalidCredentialsError("email and code required");
    const r = await this.otp.verifyOtp(email, code);
    if (!r.ok) throw new InvalidCredentialsError(r.reason);   // expired/mismatch/locked/not_found -> 401 (existing mapping)
    return toIdentityResult(r.identity);
  }
The start leg (startOtp) is invoked from the new endpoint (below), not from authenticate. This preserves the existing login-route contract: POST /api/auth/login with provider:"email", credentials:{ email, code } verifies + upserts + signs cookie exactly like mock.

== GoogleIdentityProvider becomes a thin adapter ==
Same file. Change to take a GoogleVerifier:
  constructor(private readonly verifier: GoogleVerifier | null) {}
  async authenticate(ctx) {
    if (!this.verifier) throw new NotImplementedError("google");  // 501 until GOOGLE_OAUTH_CLIENT_ID set
    const c = ctx.credentials as { idToken?: unknown };
    const idToken = typeof c?.idToken === "string" ? c.idToken : "";
    if (!idToken) throw new InvalidCredentialsError("idToken required");
    const r = await this.verifier.verify(idToken);
    if (!r.ok) throw new InvalidCredentialsError(r.reason);  // 401
    return toIdentityResult(r.identity);
  }
Google is single POST /api/auth/login with provider:"google", credentials:{ idToken } — no new endpoint, GIS does the "send" client-side.

== Which KV binding is OtpStore; which binding is EmailSender ==
- OtpStore = the existing TOKENS KV namespace (binding `TOKENS`, id `tokens_local`, already in wrangler.jsonc AND wrangler.test.jsonc). ZERO D1 schema change — honors hard-rule #2 (no new D1 table, no three-place lockstep). Wrap it in a KvOtpStore adapter (new file apps/api/src/auth/adapters.ts) that namespaces keys `otp:<normalizedEmail>` and passes expirationTtl to put. incrementAttempts is a read-modify-write `set` (KV has no atomics; the 60s resend throttle bounds the race).
- EmailSender = a NEW Cloudflare Email Sending binding `SEND_EMAIL` (send_email type), added to wrangler.jsonc ONLY (NOT wrangler.test.jsonc — like the AI binding, miniflare can't resolve it and tests run mock/no-send). Wrap it in a CfEmailSender adapter. In dev/test/mock, inject a NoopEmailSender (records nothing, zero egress).
- JwksSource = a FetchJwksSource adapter (fetch Google certs + cache by max-age) for real mode; tests inject a StaticJwksSource over a generated key.

== Zero-egress dev/test strategy (mode switch in the registry) ==
File apps/api/src/auth/registry.ts, buildIdentityProviders(env). Gate real adapters on configured secrets, exactly like the existing pattern (placeholders threaded env already):
  - email: const sender = env.EMAIL_SENDER_FROM ? new CfEmailSender(env.SEND_EMAIL, env.EMAIL_SENDER_FROM) : new NoopEmailSender(); const otp = createEmailOtpService({ store: new KvOtpStore(env.TOKENS), sender }); providers.set("email", new EmailIdentityProvider(otp)). NOTE: with NoopEmailSender the OTP is still generated+stored, so dev/e2e can verify a code (surface it via a dev-only path or a deterministic test CodeGenerator) WITHOUT egress. To keep the existing "email throws 501 in default mode" behavior for now, gate the whole service on env.EMAIL_SENDER_FROM and pass null otherwise -> NotImplementedError (501). Decision point flagged in openRisks.
  - google: const verifier = env.GOOGLE_OAUTH_CLIENT_ID ? createGoogleVerifier({ jwks: new FetchJwksSource() }, { allowedAudiences: [env.GOOGLE_OAUTH_CLIENT_ID] }) : null; providers.set("google", new GoogleIdentityProvider(verifier)). Unconfigured -> 501 (unchanged). Real JWKS fetch happens ONLY when a client id is set AND a token is verified — honors hard-rule #3 (real egress only in non-default + key present; dev bypass = null adapter).
Tests (apps/api/test) inject StaticJwksSource + an in-memory OtpStore + a fixed CodeGenerator/Clock via a test-only registry override so identity.test.ts-style tests stay zero-egress.

== Additive email-start contract + endpoint (hard-rule #1) ==
Contracts: create packages/contracts/src/auth.ts and export from packages/contracts/src/index.ts (add `export * from "./auth";`). Move the existing inline LoginRequest (app.ts:99-109) here verbatim and import it in app.ts (backward-compatible; same shape). Add:
  EmailStartRequest = z.object({ productId: ProductId, email: z.string().email(), turnstileToken: z.string().optional() })
  EmailStartResponse = z.object({ status: z.enum(["sent","throttled"]), expiresAt: z.number().int(), retryAfter: z.number().int().optional() })
All NEW fields/files are additive; existing web callers parse unchanged (LoginRequest shape preserved). This is strictly additive per hard-rule #1.

New endpoint POST /api/auth/email/start in apps/api/src/app.ts (mirror the login handler's Turnstile-first pattern):
  1. zValidator EmailStartRequest.
  2. verifyTurnstile(turnstileToken, env, ip) -> 403 on fail (reuse existing TurnstileError). Dev bypass holds (zero egress).
  3. Resolve the email provider's OtpService; call startOtp(email). (If provider is the null/501 placeholder, return 501 NOT_IMPLEMENTED — same loud failure.)
  4. Map StartOtpResult -> EmailStartResponse: {status:"sent", expiresAt} (200) or {status:"throttled", retryAfter, expiresAt} (200; throttle is not an error — web shows a countdown). No user is created and no cookie set at /start (control isn't proven yet).
The verify leg reuses POST /api/auth/login with provider:"email", credentials:{email,code} — NO second new endpoint, NO new error mapping (verifyOtp failure -> InvalidCredentialsError -> existing 401). Anonymous-session claim + cookie signing happen on the login leg, unchanged.

== Web two-step + GIS changes (apps/web) ==
- useAuthGate.ts: widen LoginSubmission to a discriminated shape: { kind:"mockCode"|"emailCode"|"google"; code?: string; email?: string; idToken?: string; turnstileToken?: string }. Add an `emailStart(email, turnstileToken?)` action that POSTs /api/auth/email/start and returns StartOtpResponse so the modal can move to the code step / show a throttle countdown. In submit(), branch the POST envelope: mockCode -> {provider:"mock", credentials:{code}}; emailCode -> {provider:"email", credentials:{email, code}}; google -> {provider:"google", credentials:{idToken}}. sessionId + turnstileToken pass through unchanged for all three.
- AuthModal.tsx: add a step state ("method" | "emailCode"). Method screen offers (a) Google Sign-In button, (b) email input -> calls gate.emailStart -> advances to emailCode step, (c) the existing demo code input may remain behind a dev flag. The emailCode step reuses the existing one-time-code input + Turnstile widget. Keep `dir="ltr"` (hard-rule #11, dream RTL must not break the shared modal).
- New apps/web/app/lib/GoogleSignIn.tsx: idempotent loader for https://accounts.google.com/gsi/client (mirror Turnstile.tsx), google.accounts.id.initialize({ client_id }) using a public client id surfaced additively via /api/auth/me (add `google: { clientId: string | null }` to the me payload — additive, like turnstile). On credential callback -> gate.submit({ kind:"google", idToken }). Renders nothing when clientId is null (dev/zero-egress).
- The api proxy route apps/web/app/routes/api.$.tsx needs NO change (transparent /api/* passthrough already covers /api/auth/email/start).

== /api/auth/me additive change ==
app.ts GET /api/auth/me: add a `google: { clientId: c.env.GOOGLE_OAUTH_CLIENT_ID ?? null }` block alongside the existing `turnstile` block. Additive (web reads it optionally), honors hard-rule #1. Surfaces only the PUBLIC client id (never a secret) — same discipline as TURNSTILE_SITE_KEY.

== wrangler / env additions ==
- apps/api/wrangler.jsonc: add a send_email binding:
    "send_email": [{ "name": "SEND_EMAIL", "destination_address": "<verified-sender@domain>" }]
  (Email Sending binding; only fires in non-mock with EMAIL_SENDER_FROM set.) Do NOT add it to wrangler.test.jsonc (keep the two configs in lockstep EXCEPT bindings miniflare can't resolve, exactly like the AI binding carve-out already documented there).
- apps/api/src/env.ts: add `SEND_EMAIL?: SendEmail` (type from @cloudflare/workers-types) to the Env interface, near the existing EMAIL_SENDER_FROM comment. GOOGLE_OAUTH_CLIENT_ID and EMAIL_SENDER_FROM already exist (reserved) — now they BECOME live gates, no rename.
- Secrets to set in production: GOOGLE_OAUTH_CLIENT_ID (also the public aud), EMAIL_SENDER_FROM. No new SESSION secret. Turnstile/session/CORS rules unchanged.

== emo hard rules that constrain each change (called out) ==
#1 contract freeze -> email-start contract is a NEW additive file; LoginRequest moved verbatim; /me gains optional google block; web callers unchanged.
#2 schema three-place lockstep -> OTP lives in TOKENS KV, ZERO D1 change (no new table, no migration, no bootstrap DDL touch). users table reused as-is for the upsert.
#3 mock boundary / zero egress -> real Email send + JWKS fetch ONLY when EMAIL_SENDER_FROM / GOOGLE_OAUTH_CLIENT_ID set AND non-mock; dev injects Noop sender + (for tests) static JWKS. SEND_EMAIL binding omitted from wrangler.test.jsonc.
#4 anonymous never calls LLM -> auth changes touch NO funnel/preview path; login still happens before generateFree; no provider call added to createSession/buildPreview.
#7 secrets never printed/committed -> public client id surfaced via /me is intentional and public; the secret (none for Google id_token verify; only the client id, which is public) and EMAIL_SENDER_FROM follow the .dev.vars discipline.
#8 web toolchain version lock -> GoogleSignIn.tsx + AuthModal changes must re-verify `pnpm --filter @app/web build` (vite 6.3.5 / RRv7 7.7.1 pinned).
#11 dream RTL + face disclaimers -> AuthModal keeps dir="ltr"; no funnel result text touched.
Provider 501 discipline (existing) -> unconfigured google/email still throw NotImplementedError -> 501; only a configured deployment flips them on, a registration change not a signature change (matches registry.ts intent).
```

### Hard rules honored (verbatim)

- #1 Contract freeze (web-facing funnel/payment/auth) is additive-ONLY: email-start lives in a NEW packages/contracts/src/auth.ts; LoginRequest is moved verbatim (same shape); /api/auth/me gains an OPTIONAL google block next to turnstile; no existing field changes type or becomes required, so current web callers parse unchanged.
- #2 Schema three-place lockstep: OTP state lives entirely in the TOKENS KV namespace — ZERO D1 change. No new table, no Drizzle migration (pnpm db:generate), no bootstrap.ts DDL. The existing users table is reused unchanged for the upsert.
- #3 Mock boundary / zero real egress in dev/test: real Email send (send_email binding) and Google JWKS fetch occur ONLY in non-mock with EMAIL_SENDER_FROM / GOOGLE_OAUTH_CLIENT_ID set; dev injects NoopEmailSender and tests inject StaticJwksSource + in-memory OtpStore. SEND_EMAIL binding is omitted from wrangler.test.jsonc (same carve-out as the AI binding).
- #4 Anonymous never calls LLM: all changes are in the auth slice; nothing touches createSession/buildPreview or the funnel. Login still gates generateFree; no provider/LLM call is added to the preview path.
- Provider 501 discipline (existing invariant): unconfigured google/email still throw NotImplementedError -> 501; flipping them live is a registration change in registry.ts (adapter injected), not an interface/signature change. InvalidCredentialsError->401 mapping is reused for verify failures.
- #7 Secrets never read-printed/committed: only the PUBLIC Google client id is surfaced via /api/auth/me (same discipline as TURNSTILE_SITE_KEY); EMAIL_SENDER_FROM and any sender creds stay in .dev.vars/secrets. SESSION_SECRET rules unchanged.
- #8 apps/web toolchain version lock (vite 6.3.5 / @cloudflare/vite-plugin 1.0.12 / react-router 7.7.1): the new GoogleSignIn.tsx + AuthModal changes MUST re-verify `pnpm --filter @app/web build` before merge.
- #9 ALLOWED_ORIGIN unchanged: the new /api/auth/email/start is a same-prefix /api/* mutation behind the existing CORS allowlist + proxy; no CORS change needed.
- #11 dream RTL + face disclaimers untouched: AuthModal keeps dir='ltr' so the shared modal reads correctly over dream's RTL funnel; no funnel result copy is modified.
- #12 registry.gen.ts / productSchemas: no product added; auth changes don't touch product registration, so no gen:registry / productSchemas edits.

### emo change plan (verbatim)

| path | change |
| --- | --- |
| `apps/api/package.json` | Add dependency "@bugbubug/auth-kit": "github:bugbubug/auth-kit#v1.0.0". (jose is a transitive dep of the SDK, not added here.) zod stays ^3.24.1. |
| `apps/api/src/auth/adapters.ts` | NEW file. Implement KvOtpStore(kv: KVNamespace) over the SDK OtpStore port (key 'otp:'+normalizedEmail; set passes {expirationTtl: ttlSeconds}; incrementAttempts = read-modify-write set; consume = delete). Implement CfEmailSender(binding: SendEmail, from: string) over EmailSender (render the OTP email + send via the send_email binding). Re-export NoopEmailSender + FetchJwksSource + StaticJwksSource from the SDK for the registry. |
| `apps/api/src/auth/identity.ts` | Add toIdentityResult(VerifiedIdentity)->IdentityResult helper. Rewrite EmailIdentityProvider to take (otp: EmailOtpService \| null): authenticate verifies credentials {email,code} via otp.verifyOtp, maps !ok->InvalidCredentialsError(reason), ok->toIdentityResult; null otp -> NotImplementedError('email'). Rewrite GoogleIdentityProvider to take (verifier: GoogleVerifier \| null): authenticate verifies credentials {idToken} via verifier.verify, maps !ok->InvalidCredentialsError(reason), ok->toIdentityResult; null verifier -> NotImplementedError('google'). MockIdentityProvider unchanged. Keep error classes + interface unchanged (frozen). |
| `apps/api/src/auth/registry.ts` | In buildIdentityProviders(env): build the email OtpService = createEmailOtpService({ store: new KvOtpStore(env.TOKENS), sender: env.EMAIL_SENDER_FROM ? new CfEmailSender(env.SEND_EMAIL, env.EMAIL_SENDER_FROM) : new NoopEmailSender() }) and pass it (or null when EMAIL_SENDER_FROM unset, to keep 501) to EmailIdentityProvider. Build the Google verifier = env.GOOGLE_OAUTH_CLIENT_ID ? createGoogleVerifier({ jwks: new FetchJwksSource() }, { allowedAudiences: [env.GOOGLE_OAUTH_CLIENT_ID] }) : null and pass to GoogleIdentityProvider. Export a buildIdentityProvidersForTest(overrides) that injects in-memory store + static JWKS for zero-egress tests. |
| `apps/api/src/auth/service.ts` | NO change to AuthService.login flow — it already authenticates via the provider and upserts by (productId, provider, providerSubject). The new providerSubjects ('email:<addr>','google:<sub>') flow through unchanged. Only re-verify the email/displayName projection still lands in the users row (it does: result.profile.email/displayName). |
| `apps/api/src/env.ts` | Add `SEND_EMAIL?: SendEmail;` (import SendEmail from @cloudflare/workers-types) near the existing EMAIL_SENDER_FROM block. Update the EMAIL_SENDER_FROM / GOOGLE_OAUTH_CLIENT_ID doc comments: they are no longer 'reserved placeholders' but the live gates that flip the email/google providers from 501 to wired (real egress only when set + non-mock). |
| `apps/api/wrangler.jsonc` | Add a send_email binding block: "send_email": [{ "name": "SEND_EMAIL", "destination_address": "<verified-sender>" }]. Leave LLM_MODE/PAYMENT_MODE/ALLOWED_ORIGIN/crons/D1/R2/AI/KV unchanged. |
| `apps/api/wrangler.test.jsonc` | Do NOT add send_email (miniflare can't resolve it; tests run mock/no-send) — extend the existing AI-binding carve-out comment to also name SEND_EMAIL as intentionally omitted, keeping the lockstep-except-unresolvable-bindings discipline. |
| `packages/contracts/src/auth.ts` | NEW file. Export LoginRequest (moved verbatim from app.ts:99-109), EmailStartRequest = z.object({ productId: ProductId, email: z.string().email(), turnstileToken: z.string().optional() }), EmailStartResponse = z.object({ status: z.enum(['sent','throttled']), expiresAt: z.number().int(), retryAfter: z.number().int().optional() }). All additive. |
| `packages/contracts/src/index.ts` | Add `export * from "./auth";` (after llm, before products) so LoginRequest + email-start contracts are web-facing and frozen-additive. |
| `apps/api/src/app.ts` | Import LoginRequest from @app/contracts instead of the inline definition (remove lines 99-109). Add POST /api/auth/email/start handler: zValidator EmailStartRequest -> verifyTurnstile (403 on fail) -> resolve email provider's OtpService -> startOtp(email) -> map to EmailStartResponse (200 sent / 200 throttled), or 501 if provider is the null placeholder. NO cookie, NO user creation at /start. /api/auth/login unchanged except provider can now be 'email'(credentials {email,code}) or 'google'(credentials {idToken}). Add a `google: { clientId: env.GOOGLE_OAUTH_CLIENT_ID ?? null }` block to GET /api/auth/me alongside `turnstile` (additive). No new error mappings needed (verify failures already -> InvalidCredentialsError->401). |
| `apps/web/app/lib/useAuthGate.ts` | Widen LoginSubmission to a tagged union { kind:'mockCode'\|'emailCode'\|'google'; code?; email?; idToken?; turnstileToken? }. Add emailStart(email, turnstileToken?) action POSTing /api/auth/email/start -> returns {status, expiresAt, retryAfter?}. Branch submit()'s POST envelope by kind (provider mock/email/google with the right credentials). sessionId + turnstileToken pass through for all. Add `google?: { clientId: string\|null }` to MeResponse and surface it on the gate. |
| `apps/web/app/lib/AuthModal.tsx` | Add step state ('method'\|'emailCode'). Method screen: Google button (GoogleSignIn) + email input (-> gate.emailStart -> step 'emailCode' / show throttle countdown on status 'throttled') + optional dev demo-code input. emailCode step reuses the one-time-code input + Turnstile widget, submits {kind:'emailCode', email, code}. Keep dir='ltr'. Update the 'Demo identity' note for the real email/Google paths. |
| `apps/web/app/lib/GoogleSignIn.tsx` | NEW file. Idempotent loader for https://accounts.google.com/gsi/client (mirror Turnstile.tsx). google.accounts.id.initialize({ client_id }) from gate.google.clientId; on credential callback -> gate.submit({ kind:'google', idToken: response.credential }). Renders nothing when clientId is null (dev zero-egress). |
| `apps/api/test/identity.test.ts` | Add cases: email start+verify happy path and each failure reason (expired/mismatch/locked/not_found) and Google verify happy/failure — all via buildIdentityProvidersForTest with in-memory OtpStore + StaticJwksSource + fixed Clock/CodeGenerator, zero egress. Confirm provider:'email'/'google' still 501 when unconfigured. |
