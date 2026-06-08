# @bugbubug/auth-kit

A **pure, hexagonal auth-VERIFICATION library**. It proves that a caller controls
an identifier (an email address, or a Google account) and hands back a single
`VerifiedIdentity`. That is the entire job.

What it deliberately does **not** do:

- It does **not** own users, sessions, or cookies.
- It does **not** decide register-vs-login or account-linking policy.
- It does **not** store user rows.
- It is **not** a deployed service. It runs **in-process** inside your own
  Worker (or any TS runtime) today, and can be wrapped as an HTTP service later
  with zero changes to this surface.

The consumer keeps all of that. The kit only answers one question — *"is this
identifier really controlled by the caller?"* — and returns the proven read of
the principal. Account ownership, the unique index, the signed session cookie,
the "is this a new user" decision: all yours.

## The two methods

| Method | Proves | `providerSubject` | How control is proven |
| --- | --- | --- | --- |
| **Email OTP** | control of an inbox | `email:<normalizedEmail>` | a code is mailed and the caller echoes it back |
| **Google id_token** | a Google-issued identity | `google:<sub>` | a GIS `id_token` is signature- and claim-verified against Google's JWKS |

Both methods return the **same** success payload:

```ts
interface VerifiedIdentity {
  providerSubject: string;   // "email:<addr>" or "google:<sub>"
  email: string;             // ALWAYS normalized: trim + lowercase
  emailVerified: boolean;    // always true on success (control was just proven)
  displayName?: string;      // Google `name` claim; absent for Email OTP
}
```

`providerSubject` carries the `email:` / `google:` prefix as part of the **frozen
format**, so two methods that resolve the same human never collide on a bare
value. For Google it is the stable `sub` claim, **never** the email.

Expected auth outcomes are returned as **discriminated unions**, never thrown.
Only programmer/config faults (a store that rejects writes, a JWKS adapter that
throws, an empty `allowedAudiences`) throw `AuthKitError`. See
[`docs/API.md`](docs/API.md) for the full reference.

## The ports

The core owns the deterministic flow; **you inject an adapter for each port**.
Adapters may be CF-specific, in-memory, or anything else — the core never knows.

| Port | What it does | Real adapter (you write / re-export) | Test adapter |
| --- | --- | --- | --- |
| `OtpStore` | persist one OTP record per email (`get` / `set` / `incrementAttempts` / `consume`) | `KvOtpStore` over a KV namespace, or a D1 table | `InMemoryOtpStore` |
| `EmailSender` | render-and-send the OTP email | `CfEmailSender` over the `send_email` binding | `NoopEmailSender` / `RecordingEmailSender` |
| `JwksSource` | supply Google's public signing keys | `FetchJwksSource` (fetches + caches Google's certs) | `StaticJwksSource(keys)` |
| `Clock` | time source (Unix epoch **ms**) | `systemClock` (built in) | a fixed clock |
| `CodeGenerator` | generate the numeric code | `defaultCodeGenerator` (built in, WebCrypto) | a deterministic generator |

`Clock` and `CodeGenerator` default to the built-in implementations when omitted,
so you only have to inject `OtpStore` + `EmailSender` (for OTP) and `JwksSource`
(for Google).

The kit ships generic `InMemoryOtpStore` / `NoopEmailSender` /
`RecordingEmailSender` / `StaticJwksSource` / `FetchJwksSource` adapters for the
non-CF cases. **CF/Workers-specific adapters (`KvOtpStore`, `CfEmailSender`) live
in the CONSUMER, not here** — they wrap your bindings, which the kit has no
business importing.

## Install

The kit ships **compiled `dist/` (ESM `.js` + `.d.ts`)** committed in the repo, so
any consumer gets prebuilt types (your `tsc` reads the `.d.ts`, skipped by
`skipLibCheck`) and prebuilt JS (your bundler — wrangler/esbuild — bundles it
directly, no build step). Pin it by **git tag**:

```bash
pnpm add github:bugbubug/auth-kit#v1.0.4
```

`jose` is a transitive dependency of the kit (used for Google signature
verification); you do not add it yourself. `zod` is an **optional** peer
(`^3.24.1`), only used by the separate, non-frozen `@bugbubug/auth-kit/zod`
input-parsing subpath — the frozen core never imports it.

## Wiring it in a Cloudflare Worker

You write two thin CF adapters (`KvOtpStore` over a KV namespace, `CfEmailSender`
over the `send_email` Email Sending binding), re-use the kit's `FetchJwksSource`,
then build the two services and glue the `VerifiedIdentity` to your own session.

```ts
import {
  createEmailOtpService,
  createGoogleVerifier,
  normalizeEmail,
  FetchJwksSource,
  type OtpStore, type OtpRecord,
  type EmailSender, type OtpEmail,
  type VerifiedIdentity,
} from "@bugbubug/auth-kit";

// ── Adapter 1: OtpStore over a KV namespace ─────────────────────────────────
// The core derives keys ("otp:<normalizedEmail>"); the adapter just stores them.
class KvOtpStore implements OtpStore {
  constructor(private kv: KVNamespace) {}
  async get(key: string): Promise<OtpRecord | null> {
    return this.kv.get<OtpRecord>(key, "json");
  }
  async set(key: string, value: OtpRecord, ttlSeconds: number): Promise<void> {
    await this.kv.put(key, JSON.stringify(value), { expirationTtl: ttlSeconds });
  }
  async incrementAttempts(key: string): Promise<number> {
    // KV has no native atomics -> read-modify-write; the 60s resend
    // throttle bounds the practical race window.
    const cur = await this.kv.get<OtpRecord>(key, "json");
    if (!cur) return 0;
    const next = { ...cur, attempts: cur.attempts + 1 };
    await this.kv.put(key, JSON.stringify(next));
    return next.attempts;
  }
  async consume(key: string): Promise<void> {
    await this.kv.delete(key); // idempotent
  }
}

// ── Adapter 2: EmailSender over the send_email binding ──────────────────────
class CfEmailSender implements EmailSender {
  constructor(private binding: SendEmail, private from: string) {}
  async send(email: OtpEmail): Promise<void> {
    // render your template from email.code + email.ttlSeconds, then send via
    // the send_email binding (throw on failure -> the core raises
    // AuthKitError("email_send_failure"), never a silent "sent").
  }
}

// ── Build the services (real mode) ──────────────────────────────────────────
export function buildAuth(env: Env) {
  const otp = createEmailOtpService({
    store: new KvOtpStore(env.TOKENS),
    sender: new CfEmailSender(env.SEND_EMAIL, env.EMAIL_SENDER_FROM),
    // codeGen + clock default to the built-ins
  });

  const google = createGoogleVerifier(
    { jwks: new FetchJwksSource() },        // the only real-egress adapter
    { allowedAudiences: [env.GOOGLE_OAUTH_CLIENT_ID] },
  );

  return { otp, google };
}

// ── Glue: VerifiedIdentity -> your app session ──────────────────────────────
// Step 1 (POST /auth/email/start): otp.startOtp(email) -> mail a code.
// Step 2 (POST /auth/login email): otp.verifyOtp(email, code).
// Google (POST /auth/login google): google.verify(idToken).
async function handleVerified(id: VerifiedIdentity, env: Env) {
  // The kit's job ends at `id`. YOU now:
  //   • upsert by (productId, "email"|"google", id.providerSubject)
  //   • project id.email / id.displayName onto the user row
  //   • sign and set YOUR session cookie
  // The kit never touched any of this.
}
```

`startOtp` returns `{ status: "sent", expiresAt }` or, inside the resend window,
`{ status: "throttled", retryAfter, expiresAt }` — throttle is **not** an error,
show a countdown. `verifyOtp` / `verify` return `{ ok: true, identity }` or
`{ ok: false, reason }` with a typed reason (see API.md). No user is created and
no cookie set until *you* decide to, after a successful verify.

## Wiring it in tests (zero egress)

Swap the three real adapters for the kit's in-memory / static ones and inject a
fixed `Clock` + deterministic `CodeGenerator`. Nothing leaves the process.

```ts
import {
  createEmailOtpService,
  createGoogleVerifier,
  InMemoryOtpStore,
  RecordingEmailSender,
  StaticJwksSource,
  type Clock, type CodeGenerator,
} from "@bugbubug/auth-kit";

const clock: Clock = { now: () => 1_700_000_000_000 };
const codeGen: CodeGenerator = { generate: () => "123456" };

const sender = new RecordingEmailSender();          // captures the OtpEmail, no send
const otp = createEmailOtpService(
  { store: new InMemoryOtpStore(clock), sender, codeGen, clock },
);

await otp.startOtp("Alice@Example.com");
sender.sent[0].code;                                // "123456" — assert without an inbox
const r = await otp.verifyOtp("alice@example.com", "123456");
// r.ok === true, r.identity.providerSubject === "email:alice@example.com"

const google = createGoogleVerifier(
  { jwks: new StaticJwksSource(testKeys), clock }, // keys you generated with jose
  { allowedAudiences: ["test-client-id"] },
);
```

`RecordingEmailSender` lets dev/e2e read the code without delivering mail;
`StaticJwksSource` lets you sign a test `id_token` with a generated keypair and
verify it offline.

## Zero-egress guarantee

The core is deterministic and makes **no network calls**. Egress happens in
**exactly two adapters**, and only when you wire the real ones:

1. **`FetchJwksSource`** — fetches Google's JWKS
   (`https://www.googleapis.com/oauth2/v3/certs`) and caches it per the response
   `Cache-Control` max-age. Only runs when you actually verify a Google token.
2. **a real `EmailSender`** (e.g. `CfEmailSender`) — sends the OTP mail.

In dev/test you inject `StaticJwksSource` + `NoopEmailSender`/`RecordingEmailSender`
and there is **zero real egress**. Google verification *always* goes through the
`JwksSource` **port** — the kit never reaches out to the network itself (no
`jose` `createRemoteJWKSet`), so a static key set fully short-circuits it.

## Defaults

| Setting | Default | Meaning |
| --- | --- | --- |
| `length` | `6` | digits in the code |
| `ttlSeconds` | `600` | code lifetime (10 minutes) |
| `resendThrottleSeconds` | `60` | minimum seconds between sends to the same email |
| `maxAttempts` | `5` | verify attempts per active code before lock |

Exported as `EMAIL_OTP_DEFAULTS`. Google issuers default to
`["https://accounts.google.com", "accounts.google.com"]` (`GOOGLE_DEFAULT_ISSUERS`);
`allowedAudiences` is **required and non-empty** — an empty list throws
`AuthKitError("config_invalid")` at construction (no wildcard audience, ever).

Password hashing (`PASSWORD_HASH_DEFAULTS`, since v1.1.0):

| Setting | Default | Meaning |
| --- | --- | --- |
| `iterations` | `100000` | PBKDF2-HMAC-SHA256 work factor |
| `saltBytes` | `16` | per-hash random salt length |
| `keyBytes` | `32` | derived key length |

The `iterations` default is `100000` because that is the **maximum Cloudflare
Workers' WebCrypto allows** for PBKDF2 — `crypto.subtle.deriveBits` throws
`NotSupportedError: iteration counts above 100000 are not supported` for anything
higher (this is why the prior `600000` default was fatal on workerd). It is the
highest value that runs unchanged on Workers, Node, and bun; a Node-only consumer
can pass a higher `iterations` (e.g. OWASP 2023's `600000`). `verifyPassword` parses
the count from the stored `pbkdf2-sha256$<iters>$…` string, so any value round-trips
and changing the default never breaks existing hashes.

## Versioning

The kit is consumed by **immutable git tag**. The frozen contract — the public
surface of `src/index.ts`, captured as the authoritative
[`etc/auth-kit.api.md`](etc/auth-kit.api.md) report (generated by
[api-extractor](https://api-extractor.com/), verified in CI by `bun run api:check`)
— is **additive-only**.

> **Tags are immutable.** Never force-move a tag. Any change ships as a new tag
> (`v1.0.1`, `v1.1.0`, …) and consumers bump their pin. A force-moved tag would
> silently shift the frozen contract under everyone pinned to it.

## License

MIT (bugbubug).
