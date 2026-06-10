/**
 * CONFIG types + their applied defaults and validators. Frozen baseline:
 * etc/auth-kit.api.md (the config shapes); the helpers below are the deterministic
 * default-application / validation logic the engine factories call.
 */

import { AuthKitError } from "./types.js";

// ───────────────────────────────────────────────────────────────────────────
// Email OTP config.
// ───────────────────────────────────────────────────────────────────────────

/** Email OTP tunables. All optional; defaults match the locked spec. */
export interface EmailOtpConfig {
  /** Digits in the code. Default 6. */
  length?: number;
  /** Code lifetime in seconds. Default 600 (10 minutes). */
  ttlSeconds?: number;
  /** Minimum seconds between sends to the same email. Default 60. */
  resendThrottleSeconds?: number;
  /** Verify attempts allowed per active code before lock. Default 5. */
  maxAttempts?: number;
}

/** The applied (no-undefined) Email OTP config, exported for callers that want the defaults. */
export const EMAIL_OTP_DEFAULTS: Required<EmailOtpConfig> = {
  length: 6,
  ttlSeconds: 600,
  resendThrottleSeconds: 60,
  maxAttempts: 5,
};

/**
 * Merge a partial EmailOtpConfig over EMAIL_OTP_DEFAULTS into a fully-applied
 * (no-undefined) config, validating every effective value. A non-positive (or
 * non-integer, non-finite) number for any field is a programmer/config fault and
 * throws AuthKitError("config_invalid") at construction — never a silent fallback.
 */
export function applyEmailDefaults(
  config?: EmailOtpConfig,
): Required<EmailOtpConfig> {
  const applied: Required<EmailOtpConfig> = {
    length: config?.length ?? EMAIL_OTP_DEFAULTS.length,
    ttlSeconds: config?.ttlSeconds ?? EMAIL_OTP_DEFAULTS.ttlSeconds,
    resendThrottleSeconds:
      config?.resendThrottleSeconds ?? EMAIL_OTP_DEFAULTS.resendThrottleSeconds,
    maxAttempts: config?.maxAttempts ?? EMAIL_OTP_DEFAULTS.maxAttempts,
  };

  for (const [key, value] of Object.entries(applied)) {
    if (!Number.isInteger(value) || value <= 0) {
      throw new AuthKitError(
        "config_invalid",
        `EmailOtpConfig.${key} must be a positive integer, got ${String(value)}`,
      );
    }
  }

  return applied;
}

// ───────────────────────────────────────────────────────────────────────────
// Google verifier config.
// ───────────────────────────────────────────────────────────────────────────

export interface GoogleVerifierConfig {
  /**
   * The OAuth client id(s) a valid id_token's `aud` must be one of. REQUIRED and
   * non-empty — an empty list throws AuthKitError("config_invalid") at
   * construction (a wildcard audience is never allowed).
   */
  allowedAudiences: string[];
  /**
   * Accepted `iss` values. Defaults to Google's two issuers:
   * ["https://accounts.google.com", "accounts.google.com"].
   */
  allowedIssuers?: string[];
}

export const GOOGLE_DEFAULT_ISSUERS: readonly string[] = [
  "https://accounts.google.com",
  "accounts.google.com",
];

/** The applied (no-undefined) Google verifier config. */
export interface AppliedGoogleConfig {
  allowedAudiences: string[];
  allowedIssuers: string[];
}

/**
 * Validate + apply defaults for a GoogleVerifierConfig. Throws
 * AuthKitError("config_invalid") when:
 *   • allowedAudiences is missing, not an array, empty, or contains a
 *     non-string / blank entry (a wildcard audience is never allowed); or
 *   • allowedIssuers is provided but empty / contains a blank entry.
 * Returns a fully-applied config with GOOGLE_DEFAULT_ISSUERS substituted when
 * allowedIssuers is omitted.
 */
export function validateGoogleConfig(
  config: GoogleVerifierConfig,
): AppliedGoogleConfig {
  const audiences = config?.allowedAudiences;
  if (!Array.isArray(audiences) || audiences.length === 0) {
    throw new AuthKitError(
      "config_invalid",
      "GoogleVerifierConfig.allowedAudiences must be a non-empty array (a wildcard audience is never allowed)",
    );
  }
  for (const aud of audiences) {
    if (typeof aud !== "string" || aud.trim() === "") {
      throw new AuthKitError(
        "config_invalid",
        "GoogleVerifierConfig.allowedAudiences entries must be non-empty strings",
      );
    }
  }

  let issuers: string[];
  if (config.allowedIssuers === undefined) {
    issuers = [...GOOGLE_DEFAULT_ISSUERS];
  } else {
    if (
      !Array.isArray(config.allowedIssuers) ||
      config.allowedIssuers.length === 0
    ) {
      throw new AuthKitError(
        "config_invalid",
        "GoogleVerifierConfig.allowedIssuers, when provided, must be a non-empty array",
      );
    }
    for (const iss of config.allowedIssuers) {
      if (typeof iss !== "string" || iss.trim() === "") {
        throw new AuthKitError(
          "config_invalid",
          "GoogleVerifierConfig.allowedIssuers entries must be non-empty strings",
        );
      }
    }
    issuers = [...config.allowedIssuers];
  }

  return { allowedAudiences: [...audiences], allowedIssuers: issuers };
}

// ───────────────────────────────────────────────────────────────────────────
// Generic OIDC verifier config.
// ───────────────────────────────────────────────────────────────────────────

/**
 * Config for the generic OIDC id_token verifier (createOidcVerifier). The
 * Google verifier is a thin preset over this engine; a new provider (Apple,
 * Microsoft, …) is just another config instance.
 */
export interface OidcVerifierConfig {
  /**
   * Accepted `iss` values. REQUIRED and non-empty — unlike the Google preset,
   * generic OIDC has no default issuers, so an empty/omitted list throws
   * AuthKitError("config_invalid") at construction.
   */
  allowedIssuers: string[];
  /**
   * The OAuth client id(s) a valid id_token's `aud` must be one of. REQUIRED
   * and non-empty — an empty list throws AuthKitError("config_invalid") at
   * construction (a wildcard audience is never allowed).
   */
  allowedAudiences: string[];
  /**
   * The provider prefix for the projected identity, e.g. "google" — produces
   * providerSubject `${subjectPrefix}:${sub}` (and VerifiedIdentity.provider).
   * REQUIRED and non-blank.
   */
  subjectPrefix: string;
  /**
   * Explicit signature-algorithm allowlist passed to jose. Defaults to
   * ["RS256"]; when provided it must be non-empty (an empty allowlist would
   * reject everything — that is a config fault, not a policy).
   */
  algorithms?: string[];
  /**
   * Whether the `email_verified` claim must be true (boolean true or the
   * string "true") for verification to succeed. Default true (the Google
   * policy). When false, an unverified email is accepted and the claim's
   * truthiness is surfaced as VerifiedIdentity.emailVerified; a usable `email`
   * claim is still REQUIRED either way (missing_email).
   */
  requireEmailVerified?: boolean;
  /** The claim projected to VerifiedIdentity.displayName. Default "name". */
  displayNameClaim?: string;
}

/** The applied (no-undefined) generic OIDC verifier config. */
export interface AppliedOidcConfig {
  allowedIssuers: string[];
  allowedAudiences: string[];
  subjectPrefix: string;
  algorithms: string[];
  requireEmailVerified: boolean;
  displayNameClaim: string;
}

/**
 * Validate + apply defaults for an OidcVerifierConfig. Throws
 * AuthKitError("config_invalid") when:
 *   • allowedIssuers is missing, not an array, empty, or contains a
 *     non-string / blank entry (generic OIDC has no default issuers); or
 *   • allowedAudiences is missing, not an array, empty, or contains a
 *     non-string / blank entry (a wildcard audience is never allowed); or
 *   • subjectPrefix is missing or blank; or
 *   • algorithms is provided but empty / contains a blank entry; or
 *   • displayNameClaim is provided but blank.
 * Returns a fully-applied config with the defaults (algorithms ["RS256"],
 * requireEmailVerified true, displayNameClaim "name") substituted when omitted.
 */
export function validateOidcConfig(
  config: OidcVerifierConfig,
): AppliedOidcConfig {
  const issuers = config?.allowedIssuers;
  if (!Array.isArray(issuers) || issuers.length === 0) {
    throw new AuthKitError(
      "config_invalid",
      "OidcVerifierConfig.allowedIssuers must be a non-empty array (generic OIDC has no default issuers)",
    );
  }
  for (const iss of issuers) {
    if (typeof iss !== "string" || iss.trim() === "") {
      throw new AuthKitError(
        "config_invalid",
        "OidcVerifierConfig.allowedIssuers entries must be non-empty strings",
      );
    }
  }

  const audiences = config.allowedAudiences;
  if (!Array.isArray(audiences) || audiences.length === 0) {
    throw new AuthKitError(
      "config_invalid",
      "OidcVerifierConfig.allowedAudiences must be a non-empty array (a wildcard audience is never allowed)",
    );
  }
  for (const aud of audiences) {
    if (typeof aud !== "string" || aud.trim() === "") {
      throw new AuthKitError(
        "config_invalid",
        "OidcVerifierConfig.allowedAudiences entries must be non-empty strings",
      );
    }
  }

  if (typeof config.subjectPrefix !== "string" || config.subjectPrefix.trim() === "") {
    throw new AuthKitError(
      "config_invalid",
      "OidcVerifierConfig.subjectPrefix must be a non-empty string",
    );
  }

  let algorithms: string[];
  if (config.algorithms === undefined) {
    algorithms = ["RS256"];
  } else {
    if (!Array.isArray(config.algorithms) || config.algorithms.length === 0) {
      throw new AuthKitError(
        "config_invalid",
        "OidcVerifierConfig.algorithms, when provided, must be a non-empty array",
      );
    }
    for (const alg of config.algorithms) {
      if (typeof alg !== "string" || alg.trim() === "") {
        throw new AuthKitError(
          "config_invalid",
          "OidcVerifierConfig.algorithms entries must be non-empty strings",
        );
      }
    }
    algorithms = [...config.algorithms];
  }

  let displayNameClaim: string;
  if (config.displayNameClaim === undefined) {
    displayNameClaim = "name";
  } else {
    if (
      typeof config.displayNameClaim !== "string" ||
      config.displayNameClaim.trim() === ""
    ) {
      throw new AuthKitError(
        "config_invalid",
        "OidcVerifierConfig.displayNameClaim, when provided, must be a non-empty string",
      );
    }
    displayNameClaim = config.displayNameClaim;
  }

  return {
    allowedIssuers: [...issuers],
    allowedAudiences: [...audiences],
    subjectPrefix: config.subjectPrefix,
    algorithms,
    requireEmailVerified: config.requireEmailVerified ?? true,
    displayNameClaim,
  };
}
