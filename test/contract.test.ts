/**
 * Frozen-seam contract test: a VerifiedIdentity maps cleanly onto emo's
 * IdentityProvider.IdentityResult shape.
 *
 * This guards the ONE integration seam the SDK exists to serve. auth-kit stays
 * standalone (it never imports emo), so the emo-side shape is mirrored here
 * locally — verbatim from apps/api/src/auth/identity.ts:
 *
 *   interface IdentityResult {
 *     providerSubject: string;
 *     profile: { email?: string; displayName?: string };
 *   }
 *
 * and the verbatim mapping from docs/FROZEN_CONTRACT.ts:
 *
 *   { providerSubject: id.providerSubject,
 *     profile: { email: id.email, displayName: id.displayName } }
 *
 * We assert it both at the TYPE level (the mapping compiles and produces exactly
 * IdentityResult — tsc is part of the gate) and at RUNTIME (a concrete identity
 * maps to the right object).
 */

import { describe, expect, it } from "vitest";

import type { VerifiedIdentity } from "../src/types.js";

// ── emo-side shape mirror (verbatim from apps/api/src/auth/identity.ts) ──────

/** emo's IdentityProvider.IdentityResult — the consumer-facing target shape. */
interface IdentityResult {
  providerSubject: string;
  profile: {
    email?: string;
    displayName?: string;
  };
}

// ── The verbatim emo glue (the one-liner from the frozen contract) ───────────

function toIdentityResult(id: VerifiedIdentity): IdentityResult {
  return {
    providerSubject: id.providerSubject,
    profile: { email: id.email, displayName: id.displayName },
  };
}

// ── Type-level assertion: the mapping's output IS assignable to IdentityResult.
// If the frozen shapes ever drift apart, this stops compiling (tsc gate).

type Assignable<From, To> = From extends To ? true : false;
type _MapsOntoIdentityResult = Assignable<
  ReturnType<typeof toIdentityResult>,
  IdentityResult
>;
// A compile-time proof the alias resolves to `true`. The unused-var is the
// assertion's whole point — referencing it keeps it load-bearing for tsc.
const _proof: _MapsOntoIdentityResult = true;
void _proof;

// Also pin the field-by-field correspondence at the type level so a rename on
// either side (e.g. VerifiedIdentity.email -> .address) breaks the build.
type _EmailIsString = Assignable<VerifiedIdentity["email"], string>;
type _SubjectIsString = Assignable<VerifiedIdentity["providerSubject"], string>;
const _fieldProofs: [_EmailIsString, _SubjectIsString] = [true, true];
void _fieldProofs;

describe("frozen seam: VerifiedIdentity -> emo IdentityResult", () => {
  it("maps a Google-style identity (with displayName) onto IdentityResult", () => {
    const id: VerifiedIdentity = {
      providerSubject: "google:1234567890",
      email: "person@example.com",
      emailVerified: true,
      displayName: "Real Person",
    };

    const result = toIdentityResult(id);

    expect(result).toEqual({
      providerSubject: "google:1234567890",
      profile: { email: "person@example.com", displayName: "Real Person" },
    });
    // providerSubject carries the provider prefix straight into emo's
    // (productId, provider, providerSubject) unique index.
    expect(result.providerSubject.startsWith("google:")).toBe(true);
    // emailVerified is intentionally dropped at this seam (always true on success).
    expect("emailVerified" in result).toBe(false);
  });

  it("maps an Email-OTP-style identity (no displayName) onto IdentityResult", () => {
    const id: VerifiedIdentity = {
      providerSubject: "email:person@example.com",
      email: "person@example.com",
      emailVerified: true,
      // displayName absent for Email OTP.
    };

    const result = toIdentityResult(id);

    expect(result.providerSubject).toBe("email:person@example.com");
    expect(result.profile.email).toBe("person@example.com");
    expect(result.profile.displayName).toBeUndefined();
  });

  it("runtime shape matches the IdentityResult contract exactly", () => {
    const id: VerifiedIdentity = {
      providerSubject: "email:a@b.com",
      email: "a@b.com",
      emailVerified: true,
    };
    const result = toIdentityResult(id);

    // Top-level keys are exactly { providerSubject, profile }.
    expect(Object.keys(result).sort()).toEqual(["profile", "providerSubject"]);
    // profile keys are a subset of { email, displayName }.
    for (const key of Object.keys(result.profile)) {
      expect(["email", "displayName"]).toContain(key);
    }
    expect(typeof result.providerSubject).toBe("string");
  });
});
