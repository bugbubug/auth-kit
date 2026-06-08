/**
 * Email OTP engine tests — fully deterministic, zero egress.
 *
 * Wiring per BUILD_PLAN finalization decision #8:
 *   • InMemoryOtpStore     (Map-backed OtpStore, fixed Clock)
 *   • RecordingEmailSender (captures sent OtpEmail; zero egress)
 *   • a fixed Clock        (mutable epoch-ms so each phase is deterministic)
 *   • a fixed CodeGenerator (returns a KNOWN code, length-checked)
 *
 * Covers: sent (records email + code length + expiry), resend-within-throttle ->
 * throttled with retryAfter, verify success -> ok + email-prefixed providerSubject
 * + single-use (second verify -> not_found), mismatch -> attempt counted, lock at
 * maxAttempts, expiry -> expired, normalization (Email+spaces == email), and the
 * hash-not-plaintext store invariant (sha-256 hex, never the code).
 */

import { describe, expect, it } from "bun:test";

import { createEmailOtpService } from "../src/email-otp.js";
import { sha256Hex } from "../src/crypto.js";
import { EMAIL_OTP_DEFAULTS } from "../src/config.js";
import { AuthKitError } from "../src/types.js";
import { otpKey } from "../src/util.js";
import { InMemoryOtpStore } from "../src/adapters/memory-otp-store.js";
import { RecordingEmailSender } from "../src/adapters/noop-email-sender.js";
import type {
  Clock,
  CodeGenerator,
  EmailSender,
  OtpEmail,
  OtpRecord,
  OtpStore,
} from "../src/ports.js";

// ── Test doubles ─────────────────────────────────────────────────────────────

/** A mutable fixed Clock: epoch ms is whatever the test sets it to. */
class FixedClock implements Clock {
  constructor(public ms: number) {}
  now(): number {
    return this.ms;
  }
  /** Advance the clock by `seconds`. */
  advanceSeconds(seconds: number): void {
    this.ms += seconds * 1000;
  }
}

/** A CodeGenerator that always returns a fixed, known code (length asserted). */
class FixedCodeGenerator implements CodeGenerator {
  constructor(private readonly code: string) {}
  generate(length: number): string {
    // The engine must request exactly the configured length.
    expect(length).toBe(this.code.length);
    return this.code;
  }
}

/**
 * A TTL-LESS OtpStore: it never self-evicts on its own. This is the store the
 * frozen contract explicitly supports ("the core ALSO enforces expiry against
 * the Clock so a TTL-less store still works", ports.ts) and is the only way to
 * deterministically exercise the CORE's Clock-enforced `expired` branch — a
 * store with exact TTL eviction (like InMemoryOtpStore) would evict the record
 * at the same instant the core would call it expired, shadowing that branch.
 */
class TtlLessOtpStore implements OtpStore {
  private readonly map = new Map<string, OtpRecord>();
  async get(key: string): Promise<OtpRecord | null> {
    const r = this.map.get(key);
    return r ? { ...r } : null;
  }
  async set(key: string, value: OtpRecord, _ttlSeconds: number): Promise<void> {
    this.map.set(key, { ...value }); // ttl ignored on purpose: no eviction.
  }
  async incrementAttempts(key: string): Promise<number> {
    const r = this.map.get(key);
    if (r === undefined) return 0;
    r.attempts += 1;
    return r.attempts;
  }
  async consume(key: string): Promise<void> {
    this.map.delete(key);
  }
}

/**
 * An EmailSender that always rejects — models a delivery adapter fault (or a
 * post-accept timeout where the mail may already be on its way). Lets us prove
 * startOtp surfaces email_send_failure WITHOUT tearing down the stored record.
 */
class ThrowingEmailSender implements EmailSender {
  async send(_email: OtpEmail): Promise<void> {
    throw new Error("smtp down");
  }
}

const KNOWN_CODE = "123456"; // 6 digits, matches the default length.
const START_MS = 1_700_000_000_000; // fixed wall-clock for determinism.

/** Build a fresh service + its injected doubles for a single test. */
function build(opts?: { clockMs?: number; code?: string }) {
  const clock = new FixedClock(opts?.clockMs ?? START_MS);
  const store = new InMemoryOtpStore(clock);
  const sender = new RecordingEmailSender();
  const codeGen = new FixedCodeGenerator(opts?.code ?? KNOWN_CODE);
  const service = createEmailOtpService({ store, sender, codeGen, clock });
  return { clock, store, sender, codeGen, service };
}

describe("Email OTP — startOtp", () => {
  it("sends: records the email, the code length, and reports expiry", async () => {
    const { service, sender, clock } = build();

    const res = await service.startOtp("user@example.com");

    expect(res.status).toBe("sent");
    // Narrow then assert expiry == now(sec) + ttl.
    if (res.status !== "sent") throw new Error("unreachable");
    const nowSec = Math.floor(clock.now() / 1000);
    expect(res.expiresAt).toBe(nowSec + EMAIL_OTP_DEFAULTS.ttlSeconds);

    // Sender recorded exactly one email to the normalized address, with the
    // plaintext code (correct length) and the ttl for copy.
    expect(sender.sent).toHaveLength(1);
    const sent = sender.sent[0];
    if (!sent) throw new Error("unreachable");
    expect(sent.to).toBe("user@example.com");
    expect(sent.code).toBe(KNOWN_CODE);
    expect(sent.code).toHaveLength(EMAIL_OTP_DEFAULTS.length);
    expect(sent.ttlSeconds).toBe(EMAIL_OTP_DEFAULTS.ttlSeconds);
  });

  it("throttles a resend inside the throttle window with retryAfter + existing expiry", async () => {
    const { service, sender, clock } = build();

    const first = await service.startOtp("user@example.com");
    expect(first.status).toBe("sent");
    if (first.status !== "sent") throw new Error("unreachable");

    // Advance only 10s (< 60s default resend throttle) and resend.
    clock.advanceSeconds(10);
    const second = await service.startOtp("user@example.com");

    expect(second.status).toBe("throttled");
    if (second.status !== "throttled") throw new Error("unreachable");
    // 60 - 10 = 50 seconds left to wait.
    expect(second.retryAfter).toBe(EMAIL_OTP_DEFAULTS.resendThrottleSeconds - 10);
    // The EXISTING (still-valid) code's expiry is echoed, not a new one.
    expect(second.expiresAt).toBe(first.expiresAt);
    // No second email went out while throttled.
    expect(sender.sent).toHaveLength(1);
  });

  it("allows a fresh send once the throttle window has elapsed", async () => {
    const { service, sender, clock } = build();

    await service.startOtp("user@example.com");
    clock.advanceSeconds(EMAIL_OTP_DEFAULTS.resendThrottleSeconds); // exactly at the edge
    const again = await service.startOtp("user@example.com");

    expect(again.status).toBe("sent");
    expect(sender.sent).toHaveLength(2);
  });

  it("does NOT throttle a resend once the existing code has EXPIRED, even inside the throttle window (no dead-window lockout)", async () => {
    // Misconfiguration the liveness gate guards against: resendThrottleSeconds >
    // ttlSeconds. With a TTL-less store the expired-but-recent record stays
    // present, so without the `now < expiresAt` gate the resend would be
    // throttled against a code verify already rejects as expired — a window
    // where the caller can neither verify nor resend.
    const clock = new FixedClock(START_MS);
    const store = new TtlLessOtpStore(); // never self-evicts
    const sender = new RecordingEmailSender();
    const codeGen = new FixedCodeGenerator(KNOWN_CODE);
    const service = createEmailOtpService(
      { store, sender, codeGen, clock },
      { ttlSeconds: 30, resendThrottleSeconds: 120 },
    );

    await service.startOtp("user@example.com");
    expect(sender.sent).toHaveLength(1);

    // Past expiry (30s) but still inside the throttle window (120s).
    clock.advanceSeconds(60);
    // Sanity: the dead record is still present in the TTL-less store.
    expect(await store.get(otpKey("user@example.com"))).not.toBeNull();

    const resend = await service.startOtp("user@example.com");
    // Not throttled: a fresh code is issued because the old one is dead.
    expect(resend.status).toBe("sent");
    expect(sender.sent).toHaveLength(2);

    // And the freshly-sent code verifies (proves a live, usable record replaced
    // the expired one rather than a throttle dead-window).
    const ok = await service.verifyOtp("user@example.com", KNOWN_CODE);
    expect(ok.ok).toBe(true);
  });

  it("still throttles a resend while the existing code is LIVE", async () => {
    // Liveness gate must not weaken the normal throttle: a live code inside the
    // window is still throttled.
    const { service, sender, clock } = build();

    const first = await service.startOtp("user@example.com");
    expect(first.status).toBe("sent");

    clock.advanceSeconds(10); // well inside both ttl (600) and throttle (60)
    const second = await service.startOtp("user@example.com");
    expect(second.status).toBe("throttled");
    expect(sender.sent).toHaveLength(1);
  });

  it("stores the code HASHED (sha-256 hex), never the plaintext", async () => {
    const { service, store } = build();

    await service.startOtp("user@example.com");

    const record = await store.get(otpKey("user@example.com"));
    expect(record).not.toBeNull();
    if (record === null) throw new Error("unreachable");

    // The stored value is the sha-256 hex of the code, not the code itself.
    expect(record.codeHash).toBe(await sha256Hex(KNOWN_CODE));
    expect(record.codeHash).not.toBe(KNOWN_CODE);
    // 32-byte sha-256 -> 64 lowercase hex chars.
    expect(record.codeHash).toMatch(/^[0-9a-f]{64}$/);
    // The plaintext code appears nowhere in the serialized record.
    expect(JSON.stringify(record)).not.toContain(KNOWN_CODE);
    expect(record.attempts).toBe(0);
  });

  it("on send failure throws email_send_failure but LEAVES the record so the (possibly delivered) code still verifies", async () => {
    // sender.send is not atomic: the email may already be delivered when send()
    // rejects. We must NOT consume the stored code — deleting it would make a
    // delivered code permanently unverifiable. Prove: startOtp rejects with
    // AuthKitError("email_send_failure"), yet the record survives and the known
    // code verifies afterward.
    const clock = new FixedClock(START_MS);
    const store = new InMemoryOtpStore(clock);
    const sender = new ThrowingEmailSender();
    const codeGen = new FixedCodeGenerator(KNOWN_CODE);
    const service = createEmailOtpService({ store, sender, codeGen, clock });

    // Capture the thrown fault ONCE (a second startOtp would be throttled by the
    // record this one stored, so assert both shape facts on the single throw).
    let caught: unknown;
    try {
      await service.startOtp("user@example.com");
    } catch (e) {
      caught = e;
    }
    // It is specifically an AuthKitError (adapter fault), not a bare Error...
    expect(caught).toBeInstanceOf(AuthKitError);
    // ...with the email_send_failure code.
    expect((caught as AuthKitError).code).toBe("email_send_failure");

    // The record was NOT consumed: it is still present in the store...
    const record = await store.get(otpKey("user@example.com"));
    expect(record).not.toBeNull();
    expect(record?.codeHash).toBe(await sha256Hex(KNOWN_CODE));

    // ...and the known code still verifies, proving a delivered-but-faulted send
    // does not strand the user.
    const ok = await service.verifyOtp("user@example.com", KNOWN_CODE);
    expect(ok.ok).toBe(true);
    if (!ok.ok) throw new Error("unreachable");
    expect(ok.identity.email).toBe("user@example.com");
  });
});

describe("Email OTP — verifyOtp", () => {
  it("succeeds: ok + email-prefixed providerSubject + emailVerified, and is single-use", async () => {
    const { service } = build();

    await service.startOtp("user@example.com");
    const ok = await service.verifyOtp("user@example.com", KNOWN_CODE);

    expect(ok.ok).toBe(true);
    if (!ok.ok) throw new Error("unreachable");
    expect(ok.identity.providerSubject).toBe("email:user@example.com");
    expect(ok.identity.email).toBe("user@example.com");
    expect(ok.identity.emailVerified).toBe(true);
    // Email OTP carries no displayName.
    expect(ok.identity.displayName).toBeUndefined();

    // Single-use: the record was consumed, so a second verify finds nothing.
    const again = await service.verifyOtp("user@example.com", KNOWN_CODE);
    expect(again).toEqual({ ok: false, reason: "not_found" });
  });

  it("not_found when no OTP was ever started for the email", async () => {
    const { service } = build();
    const res = await service.verifyOtp("nobody@example.com", KNOWN_CODE);
    expect(res).toEqual({ ok: false, reason: "not_found" });
  });

  it("mismatch consumes an attempt without consuming the record", async () => {
    const { service, store } = build();

    await service.startOtp("user@example.com");
    const bad = await service.verifyOtp("user@example.com", "000000");
    expect(bad).toEqual({ ok: false, reason: "mismatch" });

    // One attempt was counted; the record is still present.
    const record = await store.get(otpKey("user@example.com"));
    expect(record).not.toBeNull();
    expect(record?.attempts).toBe(1);

    // The correct code still verifies afterwards (record was not destroyed).
    const ok = await service.verifyOtp("user@example.com", KNOWN_CODE);
    expect(ok.ok).toBe(true);
  });

  it("locks at maxAttempts and destroys the record", async () => {
    const { service, store } = build();

    await service.startOtp("user@example.com");

    const max = EMAIL_OTP_DEFAULTS.maxAttempts; // 5
    // Attempts 1..maxAttempts-1 are plain mismatches.
    for (let i = 1; i < max; i++) {
      const r = await service.verifyOtp("user@example.com", "000000");
      expect(r).toEqual({ ok: false, reason: "mismatch" });
    }
    // The maxAttempts-th wrong attempt locks.
    const locked = await service.verifyOtp("user@example.com", "000000");
    expect(locked).toEqual({ ok: false, reason: "locked" });

    // The record is gone (consumed on lock): even the CORRECT code now 404s.
    expect(await store.get(otpKey("user@example.com"))).toBeNull();
    const afterLock = await service.verifyOtp("user@example.com", KNOWN_CODE);
    expect(afterLock).toEqual({ ok: false, reason: "not_found" });
  });

  it("expires (Clock-enforced) when the record outlives its TTL in a TTL-less store, then is consumed", async () => {
    // Use a TTL-less store so the record is still PRESENT past expiresAt; this is
    // the precise scenario the core's Clock-enforced expiry branch exists for.
    const clock = new FixedClock(START_MS);
    const store = new TtlLessOtpStore();
    const sender = new RecordingEmailSender();
    const codeGen = new FixedCodeGenerator(KNOWN_CODE);
    const service = createEmailOtpService({ store, sender, codeGen, clock });

    await service.startOtp("user@example.com");
    // Jump past expiry (>= expiresAt). The store does NOT evict, so the core's
    // own Clock check is what fires.
    clock.advanceSeconds(EMAIL_OTP_DEFAULTS.ttlSeconds + 1);
    // Sanity: the record is still in the (TTL-less) store right up until verify.
    expect(await store.get(otpKey("user@example.com"))).not.toBeNull();

    const res = await service.verifyOtp("user@example.com", KNOWN_CODE);
    expect(res).toEqual({ ok: false, reason: "expired" });

    // The expired record was consumed; a retry reports not_found.
    expect(await store.get(otpKey("user@example.com"))).toBeNull();
    const retry = await service.verifyOtp("user@example.com", KNOWN_CODE);
    expect(retry).toEqual({ ok: false, reason: "not_found" });
  });

  it("a TTL store that self-evicts at the boundary yields a valid terminal outcome (not_found)", async () => {
    // Complementary case: InMemoryOtpStore enforces an EXACT TTL, so at the
    // eviction boundary it removes the record itself and the core reads
    // not_found. Both 'expired' and 'not_found' are valid 'no active code'
    // terminals per the contract; this pins the in-memory store's behavior.
    const { service, store, clock } = build();
    await service.startOtp("user@example.com");
    clock.advanceSeconds(EMAIL_OTP_DEFAULTS.ttlSeconds + 1);

    const res = await service.verifyOtp("user@example.com", KNOWN_CODE);
    expect(res).toEqual({ ok: false, reason: "not_found" });
    expect(await store.get(otpKey("user@example.com"))).toBeNull();
  });

  it("normalizes the email: ' User@Example.COM ' starts and verifies as user@example.com", async () => {
    const { service } = build();

    const start = await service.startOtp("  User@Example.COM  ");
    expect(start.status).toBe("sent");

    // Verify with a differently-cased / un-trimmed spelling of the same address.
    const ok = await service.verifyOtp("user@example.com", KNOWN_CODE);
    expect(ok.ok).toBe(true);
    if (!ok.ok) throw new Error("unreachable");
    // The identity is the normalized form, regardless of input casing.
    expect(ok.identity.email).toBe("user@example.com");
    expect(ok.identity.providerSubject).toBe("email:user@example.com");
  });
});
