# API reference — @bugbubug/auth-kit (v1)

The authoritative surface is the api-extractor report
[`etc/auth-kit.api.md`](../etc/auth-kit.api.md), generated from `dist/index.d.ts`
and verified in CI by `bun run api:check` (it replaced the old hand-mirrored
`FROZEN_CONTRACT.ts`). `src/index.ts` is the barrel that produces it. This document
describes every export with its semantics. The contract is **additive-only**;
nothing here is removed or retyped without a new major tag.

> **v1.2.0-dev (UNRELEASED — committed after v1.1.1, not yet tagged; all
> additive):** a generic OIDC verifier engine (`createOidcVerifier` +
> `OidcVerifierDeps`/`OidcVerifier`/`OidcVerifierConfig`/`OidcFailureReason`/
> `VerifyOidcResult`) that `createGoogleVerifier` is now a thin preset over; an
> optional `VerifiedIdentity.provider` discriminant (always populated by the
> engines); and a configurable `timeoutMs` on the `FetchJwksSource` adapter.

All exports are imported from the package root:

```ts
import { /* ... */ } from "@bugbubug/auth-kit";
```

The optional input-parsing helpers live at `@bugbubug/auth-kit/zod` (separate,
non-frozen subpath, imports the `zod` peer). The frozen core below is zod-free.

---

## 1. Output type: `VerifiedIdentity`

The verified read of the principal behind a proven identifier. The **only**
success payload either method returns.

```ts
interface VerifiedIdentity {
  providerSubject: string;
  provider?: string;        // v1.2.0-dev (additive)
  email: string;
  emailVerified: boolean;
  displayName?: string;
}
```

| Field | Semantics |
| --- | --- |
| `providerSubject` | The provider's stable, opaque subject. **Email OTP:** `email:<normalizedEmail>` (control of the address *is* the id). **Google:** `google:<sub>` — Google's stable `sub` claim, **never** the email. The `<provider>:` prefix is part of the frozen format so the two methods never collide on a bare value. |
| `provider?` | *(v1.2.0-dev)* The verification method that produced this identity — `"email"` for Email OTP, `"google"` for the Google preset, the configured `subjectPrefix` for a generic OIDC verifier. Matches the `providerSubject` prefix, so consumers no longer need to parse it. Optional in the type (frozen-contract compatibility) but **always populated** by the engines from v1.2. |
| `email` | The address, **always normalized** (trim + lowercase). For OTP, the verified address; for Google, the `email` claim (present only when `emailVerified` is true). |
| `emailVerified` | Whether the email is provider-verified. **Email OTP:** always `true` (the inbox was just proven). **Google:** mirrors `email_verified`; the verifier *requires* it true to succeed, so in practice always `true` on success. Surfaced explicitly so the consumer's linking policy reads it rather than re-deriving it. |
| `displayName?` | Optional human-friendly name (Google `name` claim). **Absent** for Email OTP. |

---

## 2. Result model (discriminated unions — expected outcomes)

Expected, caller-recoverable outcomes are **returned**, never thrown. Only
programmer/config faults throw (`AuthKitError`, §3).

### `StartOtpResult`

```ts
type StartOtpResult =
  | { status: "sent";      expiresAt: number }
  | { status: "throttled"; retryAfter: number; expiresAt: number };
```

| Variant | Meaning |
| --- | --- |
| `sent` | A fresh code was generated, hashed, stored, and sent. `expiresAt` = Unix epoch **seconds** the code expires. |
| `throttled` | A recent code is still inside the resend window; **no** new code was sent. `retryAfter` = seconds to wait before another send; `expiresAt` = expiry of the **existing** still-valid code. Throttle is **not** an error — show a countdown. |

### `OtpFailureReason` / `VerifyOtpResult`

```ts
type OtpFailureReason = "expired" | "mismatch" | "locked" | "not_found";

type VerifyOtpResult =
  | { ok: true;  identity: VerifiedIdentity }
  | { ok: false; reason: OtpFailureReason };
```

| Reason | Meaning |
| --- | --- |
| `expired` | No active code (TTL elapsed). Caller should restart. |
| `mismatch` | Code did not match; **an attempt was consumed**. |
| `locked` | `maxAttempts` reached for the active code; the record is consumed. Caller must restart. |
| `not_found` | No OTP was ever started for this email, or it was already consumed (single-use). |

### `GoogleFailureReason` / `VerifyGoogleResult`

```ts
type GoogleFailureReason =
  | "malformed" | "bad_signature" | "untrusted_issuer" | "untrusted_audience"
  | "expired" | "email_unverified" | "missing_email";

type VerifyGoogleResult =
  | { ok: true;  identity: VerifiedIdentity }
  | { ok: false; reason: GoogleFailureReason };
```

| Reason | Meaning |
| --- | --- |
| `malformed` | Not a parseable / structurally-valid JWT. |
| `bad_signature` | Signature did not verify against the JWKS. |
| `untrusted_issuer` | `iss` not in `allowedIssuers`. |
| `untrusted_audience` | `aud` not in `allowedAudiences`. |
| `expired` | `exp` in the past (or `nbf`/`iat` invalid) per the injected `Clock`. |
| `email_unverified` | `email_verified` claim is not true. |
| `missing_email` | No usable `email` claim present. |

### `OidcFailureReason` / `VerifyOidcResult`  *(v1.2.0-dev)*

```ts
type OidcFailureReason = GoogleFailureReason; // identical reason set
type VerifyOidcResult  = VerifyGoogleResult;  // identical result shape
```

The generic OIDC engine (`createOidcVerifier`, §6) produces the exact same
reason set as the Google verifier — Google **is** a preset of that engine — so
these are additive type aliases, not new unions. Use them at OIDC-generic call
sites so the code doesn't name a Google-specific type.

---

## 3. `AuthKitError`

```ts
class AuthKitError extends Error {
  readonly code:
    | "store_failure"
    | "jwks_failure"
    | "email_send_failure"
    | "config_invalid";
  constructor(code: AuthKitError["code"], message: string, options?: { cause?: unknown });
}
```

Thrown **only** for programmer/configuration faults the caller cannot recover from
at runtime. Expected auth outcomes are **never** thrown — they come back in the
unions above. `code` is a stable machine string.

| `code` | Raised when |
| --- | --- |
| `store_failure` | An `OtpStore` operation throws. |
| `jwks_failure` | The `JwksSource` adapter throws. |
| `email_send_failure` | The `EmailSender` throws — the core surfaces it rather than silently reporting `sent`. |
| `config_invalid` | Malformed config at construction (e.g. empty `allowedAudiences`, a non-positive numeric tunable). |

---

## 4. Ports (consumer injects an adapter for each)

### `Clock`

```ts
interface Clock { now(): number; } // Unix epoch MILLISECONDS (matches Date.now())
```

Inject a fixed clock in tests for determinism. Defaults to `systemClock` when omitted.

### `CodeGenerator`

```ts
interface CodeGenerator { generate(length: number): string; } // numeric, exactly `length` digits, zero-padded
```

Defaults to `defaultCodeGenerator` (WebCrypto, no modulo bias) when omitted.

### `OtpRecord`

```ts
interface OtpRecord {
  codeHash: string;   // sha-256(code) as lowercase hex — plaintext code is NEVER stored
  expiresAt: number;  // Unix epoch SECONDS
  issuedAt: number;   // Unix epoch SECONDS (drives the resend throttle)
  attempts: number;   // attempts consumed against this code
}
```

The record the `OtpStore` persists per email. Opaque to adapters except they must
round-trip every field.

### `OtpStore`

```ts
interface OtpStore {
  get(key: string): Promise<OtpRecord | null>;
  set(key: string, value: OtpRecord, ttlSeconds: number): Promise<void>;
  incrementAttempts(key: string): Promise<number>;
  consume(key: string): Promise<void>;
}
```

Persistence port. Keys are **derived by the core** from the normalized email
(`otp:<normalizedEmail>`); the consumer never builds keys.

- `get` — active record for `key`, or `null` if absent/evicted.
- `set` — write/overwrite the active record. `ttlSeconds` is the remaining
  lifetime; KV adapters pass it to `put(..., { expirationTtl })`. The core *also*
  enforces expiry against the `Clock`, so a TTL-less store still works. Throw →
  `AuthKitError("store_failure")`.
- `incrementAttempts` — atomically increment `attempts`, return the **new** count.
  Called on each mismatch so the core can lock at `maxAttempts` without a
  read-modify-write race. For KV (no native atomics) the adapter may RMW `set`;
  the resend throttle bounds the practical race window.
- `consume` — delete the record (on success and on lock). **Idempotent.**

### `OtpEmail`

```ts
interface OtpEmail {
  to: string;          // normalized recipient
  code: string;        // plaintext code, for the body
  ttlSeconds: number;  // seconds until expiry, for copy
}
```

What the core hands the `EmailSender`. The core supplies code+ttl; the adapter
owns the template.

### `EmailSender`

```ts
interface EmailSender { send(email: OtpEmail): Promise<void>; }
```

Outbound email port. The real adapter sends; the dev/test adapter is a no-op or
records to an array (zero egress). Throw → `AuthKitError("email_send_failure")`.

### `Jwk` / `JwksSource`

```ts
interface Jwk { kid?: string; kty: string; alg?: string; use?: string; n?: string; e?: string; [claim: string]: unknown; }
interface JwksSource { getKeys(): Promise<{ keys: Jwk[] }>; }
```

Source of the provider's public signing keys. The bundled `FetchJwksSource`
adapter (`src/adapters/`, off the frozen barrel) defaults to Google's
`https://www.googleapis.com/oauth2/v3/certs`, accepts any JWKS `url`, and caches
per `Cache-Control` max-age — **egress happens only here, only when verifying
for real**. Its whole-operation abort deadline (armed across both the fetch and
the body read) is configurable via `FetchJwksOptions.timeoutMs`
(*v1.2.0-dev*; default 5000, a non-positive/non-integer value throws
`AuthKitError("config_invalid")` at construction). Tests inject a static set
(zero egress). The verifier selects the key by `kid`. The kit never uses
`jose.createRemoteJWKSet`; verification always routes through this port.

---

## 5. Config

### `EmailOtpConfig` + defaults

```ts
interface EmailOtpConfig {
  length?: number;
  ttlSeconds?: number;
  resendThrottleSeconds?: number;
  maxAttempts?: number;
}

const EMAIL_OTP_DEFAULTS: Required<EmailOtpConfig>; // { length: 6, ttlSeconds: 600, resendThrottleSeconds: 60, maxAttempts: 5 }
```

| Field | Default | Meaning |
| --- | --- | --- |
| `length` | `6` | digits in the code |
| `ttlSeconds` | `600` | code lifetime (10 minutes) |
| `resendThrottleSeconds` | `60` | minimum seconds between sends to the same email |
| `maxAttempts` | `5` | verify attempts per active code before lock |

**Validation:** each effective value must be a **positive integer**. A
non-integer, non-finite, or `<= 0` value for any field throws
`AuthKitError("config_invalid")` at construction — never a silent fallback.

### `GoogleVerifierConfig` + default issuers

```ts
interface GoogleVerifierConfig {
  allowedAudiences: string[];   // REQUIRED, non-empty
  allowedIssuers?: string[];    // defaults to GOOGLE_DEFAULT_ISSUERS
}

const GOOGLE_DEFAULT_ISSUERS: readonly string[]; // ["https://accounts.google.com", "accounts.google.com"]
```

**Validation** (`AuthKitError("config_invalid")` at construction):

- `allowedAudiences` must be a **non-empty array of non-empty strings**. Missing,
  not an array, empty, or any blank/non-string entry throws. A **wildcard
  audience is never allowed.**
- `allowedIssuers`, **when provided**, must be a non-empty array of non-empty
  strings (same rules). When omitted, `GOOGLE_DEFAULT_ISSUERS` is substituted.

### `OidcVerifierConfig`  *(v1.2.0-dev)*

```ts
interface OidcVerifierConfig {
  allowedIssuers: string[];      // REQUIRED, non-empty — generic OIDC has NO default issuers
  allowedAudiences: string[];    // REQUIRED, non-empty (wildcard never allowed)
  subjectPrefix: string;         // REQUIRED, non-blank — providerSubject = `${subjectPrefix}:${sub}`
  algorithms?: string[];         // default ["RS256"]; non-empty when provided
  requireEmailVerified?: boolean;// default true (the Google policy)
  displayNameClaim?: string;     // default "name"
}
```

Config for the generic OIDC engine (§6). All the validation rules above apply
per field (`AuthKitError("config_invalid")` at construction). With
`requireEmailVerified: false`, an unverified email is accepted and the claim's
truthiness is surfaced as `VerifiedIdentity.emailVerified`; a usable `email`
claim is still **required** either way (`missing_email`).

---

## 6. Engine factories

### Email OTP

```ts
interface EmailOtpDeps {
  store: OtpStore;
  sender: EmailSender;
  codeGen?: CodeGenerator;  // defaults to defaultCodeGenerator
  clock?: Clock;            // defaults to systemClock
}

interface EmailOtpService {
  startOtp(email: string): Promise<StartOtpResult>;
  verifyOtp(email: string, code: string): Promise<VerifyOtpResult>;
}

function createEmailOtpService(deps: EmailOtpDeps, config?: EmailOtpConfig): EmailOtpService;
```

- **`startOtp(email)`** — normalize the address, enforce the resend throttle,
  generate + sha-256-hash + store a fresh code, and send it. Returns `sent` with
  expiry, or `throttled` with `retryAfter` when a recent code is still inside the
  window. Throws `AuthKitError` only on a store/sender fault. No user, no cookie —
  control isn't proven yet.
- **`verifyOtp(email, code)`** — on success returns the `VerifiedIdentity`
  (`providerSubject` = `email:<addr>`, `emailVerified: true`) and **consumes** the
  record (single-use). On failure returns a typed `OtpFailureReason`; a mismatch
  consumes an attempt and **locks** at `maxAttempts`. The plaintext code is
  compared **constant-time** against the stored hash. Never throws for an expected
  failure.

### Google id_token

```ts
interface GoogleVerifierDeps {
  jwks: JwksSource;
  clock?: Clock;            // defaults to systemClock
}

interface GoogleVerifier {
  verify(idToken: string): Promise<VerifyGoogleResult>;
}

function createGoogleVerifier(deps: GoogleVerifierDeps, config: GoogleVerifierConfig): GoogleVerifier;
```

- **`verify(idToken)`** — parse, select the signing key by `kid`, verify the
  signature against the JWKS with `jose`, then check `iss ∈ allowedIssuers`,
  `aud ∈ allowedAudiences`, `exp`/`iat` per the `Clock`, and **require**
  `email_verified`. Returns the `VerifiedIdentity` (`providerSubject`
  = `google:<sub>`, `provider: "google"`, normalized email, `displayName` from
  `name`) or a typed `GoogleFailureReason`. Never throws for an expected
  verification failure; a JWKS adapter fault throws `AuthKitError("jwks_failure")`.
- Since v1.2.0-dev this is a **thin preset over `createOidcVerifier`**:
  `validateGoogleConfig` (issuer defaulting + Google error messages) runs first,
  then delegates with `subjectPrefix: "google"` and the engine defaults
  (RS256, `requireEmailVerified: true`). Behavior is unchanged.

### Generic OIDC id_token  *(v1.2.0-dev)*

```ts
interface OidcVerifierDeps {
  jwks: JwksSource;
  clock?: Clock;            // defaults to systemClock
}

interface OidcVerifier {
  verify(idToken: string): Promise<VerifyOidcResult>;
}

function createOidcVerifier(deps: OidcVerifierDeps, config: OidcVerifierConfig): OidcVerifier;
```

The engine the Google verifier is a preset of. Same pipeline (structural parse →
local JWKS via the injected port → `jose` verify with the `algorithms` allowlist
+ `requiredClaims: ["exp"]` + injected-Clock `currentDate` → claim policy →
projection), parameterized by `OidcVerifierConfig` (§5). A new provider
(Apple, Microsoft, …) is just another config instance:

```ts
const apple = createOidcVerifier(
  { jwks: new FetchJwksSource({ url: "https://appleid.apple.com/auth/keys" }) },
  {
    allowedIssuers: ["https://appleid.apple.com"],
    allowedAudiences: [env.APPLE_CLIENT_ID],
    subjectPrefix: "apple",
  },
);
```

Projects `providerSubject = "<subjectPrefix>:<sub>"` and
`provider = subjectPrefix`. Never throws for an expected verification failure;
a JWKS adapter fault throws `AuthKitError("jwks_failure")`; an invalid config
throws `AuthKitError("config_invalid")` at construction.

---

## 7. Built-in helpers

```ts
const defaultCodeGenerator: CodeGenerator; // WebCrypto, uniform digits, no modulo bias
const systemClock: Clock;                  // Date.now()-backed (ms)
function normalizeEmail(raw: string): string; // trim + lowercase
```

`normalizeEmail` is exported so consumers normalize identically to the core when
matching keys/users (the same form used for the `email:<addr>` `providerSubject`
and the `otp:<addr>` store key).

---

## 8. Consumer mapping — `VerifiedIdentity` → emo `IdentityResult`

emo's `IdentityResult` is `{ providerSubject, profile: { email?, displayName? } }`.
The one-line glue used by **both** providers:

```ts
function toIdentityResult(id: VerifiedIdentity): IdentityResult {
  return {
    providerSubject: id.providerSubject,           // "email:<addr>" | "google:<sub>"
    profile: { email: id.email, displayName: id.displayName },
  };
}
```

- `providerSubject` already carries the `email:` / `google:` prefix, so it slots
  straight into emo's `(productId, provider, providerSubject)` unique index.
  Since v1.2.0-dev `id.provider` carries the same discriminant directly — read
  it instead of parsing the prefix.
- `email` is already normalized — no further work to match user rows.
- `emailVerified` is **dropped at this seam** (always `true` on success). Read it
  *before* mapping if account-linking policy needs it.
- `displayName` flows through (present for Google, absent for Email OTP).

In emo's adapters the thin providers verify then map: a `!ok` result becomes
`InvalidCredentialsError(reason)` → existing 401 mapping; an unconfigured provider
stays `NotImplementedError` → 501. `AuthKitError` (adapter/config fault) is a
genuine 500-class fault, distinct from these expected auth outcomes.
