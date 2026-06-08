// @ts-check
/**
 * Flat ESLint config for @bugbubug/auth-kit.
 *
 * Its PRIMARY job is to enforce the core import boundary that keeps the frozen
 * engine's third-party runtime import graph minimal and portable — the cheap,
 * CI-decidable proxy that replaces the old hand-rolled purity scan:
 *
 *   Under src/**, importing `zod`, `hono`, `@cloudflare/workers-types`, or ANY
 *   Node builtin (bare `crypto`/`fs`/`path`/… AND the `node:*` prefix form) is
 *   FORBIDDEN. The core runs on WebCrypto + `jose` only, so it executes
 *   unchanged on workerd / bun / Node — `jose` is a real dependency and stays
 *   allowed.
 *
 * Two seams are EXEMPT from the boundary (they are not part of the frozen core):
 *   • src/zod.ts        — the optional, off-barrel `/zod` subpath that imports
 *                         the zod peer.
 *   • src/adapters/**   — optional adapters (they use the `fetch`/`crypto`
 *                         globals, never node:* imports, but the exemption keeps
 *                         the boundary about the CORE only).
 */

import js from "@eslint/js";
import tseslint from "typescript-eslint";

/**
 * The forbidden import targets for the core. Node builtins are listed both bare
 * and `node:`-prefixed; the prefix form is covered by a pattern below.
 */
const FORBIDDEN_PATHS = [
  { name: "zod", message: "The frozen core must not import zod — use the off-barrel /zod subpath (src/zod.ts)." },
  { name: "hono", message: "The frozen core must not import hono — it stays framework-agnostic." },
  {
    name: "@cloudflare/workers-types",
    message: "The frozen core must not import @cloudflare/workers-types — CF-specific code lives in the consumer.",
  },
  // Bare Node builtins (the consumer/runtime provides WebCrypto + fetch globals).
  "assert", "buffer", "child_process", "cluster", "console", "constants",
  "crypto", "dgram", "dns", "domain", "events", "fs", "http", "http2",
  "https", "module", "net", "os", "path", "perf_hooks", "process",
  "punycode", "querystring", "readline", "repl", "stream", "string_decoder",
  "timers", "tls", "tty", "url", "util", "v8", "vm", "worker_threads", "zlib",
];

const noRestrictedImports = [
  "error",
  {
    paths: FORBIDDEN_PATHS,
    patterns: [
      {
        // Any `node:*` builtin (node:crypto, node:fs, …) in the core.
        group: ["node:*"],
        message: "The frozen core must not import Node builtins (node:*) — it uses WebCrypto + fetch globals only.",
      },
    ],
  },
];

export default [
  {
    ignores: ["dist/**", "node_modules/**", "coverage/**", "etc/**", "temp/**"],
  },
  // Apply the base recommended JS rules, but ONLY to TS sources/tests — the
  // typescript-eslint PARSER (no typed-linting, no tsconfig project) handles the
  // TS syntax so the syntactic `no-restricted-imports` rule can read the imports.
  {
    files: ["src/**/*.ts", "test/**/*.ts"],
    ...js.configs.recommended,
    languageOptions: {
      ...js.configs.recommended.languageOptions,
      ecmaVersion: "latest",
      sourceType: "module",
      parser: tseslint.parser,
    },
    rules: {
      ...js.configs.recommended.rules,
      // TypeScript's own tsc gate handles unused/undef far more precisely than
      // core ESLint; the recommended set's no-undef/no-unused-vars false-flag
      // TS-only constructs (type-only imports, ambient globals, interfaces), so
      // disable them here. The import-boundary rule below is the load-bearing
      // check this config exists for.
      "no-unused-vars": "off",
      "no-undef": "off",
    },
  },
  {
    // Core source files: enforce the import boundary.
    files: ["src/**/*.ts"],
    rules: {
      "no-restricted-imports": noRestrictedImports,
    },
  },
  {
    // EXEMPT seams: the off-barrel /zod subpath and the optional adapters are
    // outside the frozen core, so the boundary does not apply to them.
    files: ["src/zod.ts", "src/adapters/**/*.ts"],
    rules: {
      "no-restricted-imports": "off",
    },
  },
];
