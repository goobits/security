# Changelog

All notable changes to `@goobits/security` are documented here. The format adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- CHANGELOG audit cutoff: 2026-06-24. commit 06d1824 on main. -->

## [Unreleased]

### Added

- **`redaction`**: Added `redactSecretText()` for credentials embedded in
  environment assignments, authorization headers, and URLs.
- A publish-only compiled ESM artifact with declarations and an isolated
  tarball smoke test for every public entrypoint. Workspace consumers continue
  to use the existing source exports.
- `request-origin`: one framework-agnostic verifier for Fetch Metadata,
  `Origin`, and `Referer` checks across browser mutation boundaries.
- `audit`: explicit `failureMode: 'throw'` support for required durable audit
  pipelines, and `safeErrorContext()` for bounded error logging.
- `runtime`: public `readRuntimeEnv()` and `isProductionRuntime()` helpers so
  packages and applications share one production-safe runtime decision.
- A shared `PrincipalIdentity` base type for verified identity, principal-auth,
  and admin-auth results.

### Changed

- `rate-limit`: added one generic resilient-store wrapper with an explicit
  `closed | fallback` failure policy. Fallback mode requires a caller-owned
  store, and observer failures cannot change the selected policy.
- Unknown runtime modes now use production-safe defaults; development bypasses
  require an explicit `NODE_ENV=development` or `NODE_ENV=test`.
- Audit redaction defaults can only be extended, not disabled, and arbitrary
  exception messages and stacks are excluded from default projections.
- Trusted client-IP headers are bounded and validated before use.
- D1 rate-limit storage now accepts only the canonical JSON timestamp format;
  the expired numeric-counter migration bridge was removed.
- Principal authentication validates and bounds principal IDs, roles, API-key
  mappings, header names, algorithms, token lifetimes, and expected claims at
  construction or signing time. API keys must be unique and contain 32-4096
  bytes.
- The successful API-key authentication method is consistently named
  `api-key` instead of `apikey`.
- D1 audit sinks now propagate write failures after bounded logging so the
  owning `AuditLogger` can honor its configured `report` or `throw` policy.
- Runtime checks distinguish an omitted argument from an explicitly absent
  deployment binding; explicit unknown bindings always retain production-safe
  behavior.

## [3.0.0] - 2026-07-16

### Breaking

- The internal `resolveLogger()` fallback is no longer exported from `@goobits/security/logger`. Consumers should pass a logger to public factories or use the exported `noopLogger` explicitly. This closes the logger surface around stable public contracts ahead of v3.
- Authentication-specific rate-limit presets moved to `@goobits/auth/security`.
  `@goobits/security/rate-limit` now owns only the generic counter mechanism,
  and the `rate-limit/auth` subpath has been removed.
- The root-only `SECURITY_PACKAGE_VERSION` constant was removed. Package
  metadata is not a runtime security primitive; read the installed manifest when
  tooling needs a version.

### Removed

- Removed legacy boolean CAPTCHA helpers. Use `verifyRecaptcha()` and `verifyTurnstile()` directly so callers can branch on structured failure reasons instead of flattening security decisions to `true`/`false`.
- Removed the unused `ioredis` peer and development dependency. Redis-backed
  CSRF remains client-agnostic through the public `RedisLike` contract.
- Stopped exporting the private request-body and cookie parser helper types.

### ✨ Added

- **`redaction`**: Normalized secret-key detection and recursive omission for
  public projections, including common camel-case, snake-case, and kebab-case
  variants.
- **`http-credentials`**: Strict, bounded parsers for Basic, Bearer, and explicit API-key authorization headers; constant-work Basic password verification; HMAC-bound API-key verifiers; secure key generation; and sanitized challenge responses.
- **`redaction`**: Recursive, cycle-safe structured-value redaction with conservative secret-key defaults and consumer-provided string scrubbing for application PII policy.
- **`crypto`**: Opaque, rotation-ready AES-GCM keyrings that expose key IDs without exposing key material.
- **`rate-limit`**: HMAC-backed store wrapper that keeps raw emails, usernames, IP addresses, and tokens out of rate-limit persistence while propagating backing-store failures for explicit consumer policy.
- **`csrf/sveltekit`**: New SvelteKit adapter for stateless double-submit
  cookies, bounded form/JSON token extraction, and unsafe-method middleware.
- 🌐 **`turnstile`**: New `@goobits/security/turnstile` sub-export for Cloudflare Turnstile token verification with the same discriminated-union result shape as `recaptcha`.
- 🔒 **`csp`**: CSP3 and Trusted Types directives are now supported by the CSP builder.
- 📦 **`rate-limit`**: `peek()` exposes limiter state without incrementing counters.
- **`crypto`**: New `@goobits/security/crypto` sub-export with framework-agnostic Web Crypto helpers for encoding, random bytes/hex, SHA-256, constant-time comparison, HMAC signatures, AES-GCM sealing/opening, and deterministic `SecurityProof` envelopes. Adds narrower sub-exports for `crypto/encoding`, `crypto/signatures`, `crypto/aead`, and `crypto/proof` so auth/session and decentralized protocol packages can share one primitive layer without product-specific permissions.
- **`identity`**: New `@goobits/security/identity` sub-export with generic DID-WBA and HTTP Signature identity adapters. The adapters parse and validate request identity envelopes, enforce timestamp/domain checks, and call a consumer-supplied signature verifier so protocol packages can plug in their own key resolution without making this package Goobits-product-specific.
- **`principal-auth`**: New generic `@goobits/security/principal-auth` sub-export for JWT/API-key principal authentication. `admin-auth` now delegates to this shared implementation and remains as a focused adapter for admin-only routes.

### 🔧 Changed

- 🛡️ **`csrf`**: Store failures during requested expiry checks now fail closed
  by default. Availability-sensitive callers must opt out explicitly.
- 🔔 **`alerting`**: Added one generic, store-backed threshold observer and a
  single `info | warning | critical` severity vocabulary for consumer packages.
- 📦 **module layout**: CSRF and bounded request-body primitives now live at
  honest public module paths (`csrf.ts` and `request-body`) instead of private or
  implementation-named files. Existing `validation/sveltekit` re-exports remain
  available for compatibility.
- **`csrf` / `rate-limit`**: In-memory stores now enforce deterministic
  configurable `maxKeys` bounds, cleaning stale entries before evicting the
  oldest active key.
- **Request bodies**: Oversized cloned-body cancellation is non-blocking so a
  rejected inspection cannot deadlock while the original request remains
  available to the host framework.
- 🔔 **`alerting`**: Webhook delivery now aborts after a configurable timeout
  (`5000ms` by default) instead of waiting indefinitely on an unavailable receiver.
- 🧮 **`rate-limit`**: Limiter construction now rejects empty names and
  non-positive, fractional, non-finite, or unsafe window values.
- 📦 **`validation/sveltekit`**: Validation options now satisfy exact optional property types without weakening public option shapes.

### 🏠 Internal

- 📚 README guidance refreshed for source-level distribution and current app paths.
- 🧪 Timing-sensitive security tests now document their probes more clearly.
- 📦 Development dependencies refreshed for the current package toolchain.

## [2.0.0] - 2026-05-18

### Distribution

- **Source-only distribution via git submodule.** `package.json#exports` now points directly at `./src/*.ts`. No build step, no `dist/`, no npm publish. Consumers add this repo as a git submodule, wire it into their `pnpm-workspace.yaml`, and their bundler (Vite/esbuild/SvelteKit) compiles the source as part of its own pipeline. Removed: `tsup`, `tsup.config.ts`, `@arethetypeswrong/*`, `publint`, `scripts/attw.mjs`, the `build` / `dev` / `attw` / `publint` / `prepublishOnly` scripts.

### Hardening pass (pre-release)

Security

- **`recaptcha`**: `allowInDevelopment` default flipped from `true` to `false`. Closes a silent-bypass foot-gun on runtimes that don't set `NODE_ENV` (Cloudflare Workers, Deno, CI). Consumers who relied on the old behavior must now pass `{ allowInDevelopment: true }` explicitly.
- **`admin-auth`**: swapped `jsonwebtoken` (CJS, Node-only) for [`jose`](https://github.com/panva/jose) (Web Crypto, cross-runtime). The module now genuinely loads on Cloudflare Workers, Deno, and Bun. `createAdminToken` is now `async`.
- **`admin-auth`**: JWT verification now pins `algorithms: ['HS256']` by default (overridable via `algorithms` config). Defense-in-depth against future jsonwebtoken-style regressions and algorithm-confusion attacks.
- **`admin-auth`**: `jwtSecret` is now validated to be ≥32 characters at `createAdminAuth()` time. Throws loudly on weak secrets.
- **`csrf`**: `DISABLE_CSRF` now throws at `createCsrf()` time when `NODE_ENV === 'production'`. Previously it only logged. Fixes JSDoc-vs-implementation drift.
- **`csrf`**: Added `failClosed?: boolean` option - store errors return `false` from `validate()` when set. Default remains fail-open (availability over correctness); compliance-sensitive routes can opt in.
- **`rate-limit`**: `MemoryRateLimitStore` now performs opportunistic cleanup (~1% chance per increment) to bound memory growth on attacker-rotated identifiers.
- **`rate-limit`**: `getClientIP` now requires explicit `trustHeaders` opt-in. By default returns `'unknown'` - refuses to blindly trust spoof-friendly proxy headers.
- **`_internal/cookies`**: `serializeCookie` now validates cookie name + value against RFC 6265 character classes. Throws on CRLF / `;` / `,` / `\` / `"` / space in values (mitigates header-injection latent risk).

API + types

- **`audit`**: `withAudit` adds `redactKeys` option, defaulting to `['password', 'token', 'secret', 'apiKey', 'authorization', 'creditCard', 'cvv']`. Request body capture (`includeRequestBody: true`) now strips these fields before logging. Pass `redactKeys: []` to disable explicitly.
- **`audit`**: documented fire-and-forget dispatch semantics + outcome derivation rules in JSDoc.
- **`audit`**: caller-supplied `timestamp` in `auditor.log({ timestamp })` now correctly takes precedence (was always being overwritten by spread order).
- **`alerting`**: `Alert.source` widened from literal `'goobits/security'` to `string`. Lets app code reuse the same channels for its own alerts.
- **`rate-limit`**: removed dead `setEntry` method from `RateLimitStore` interface (was never called and the in-memory implementation ignored its `ttlMs` arg).
- **`rate-limit`**: `RateLimitResult.window` is now also populated on the `allowed: true` branch (was previously only on `allowed: false`), so consumers can emit `X-RateLimit-*` headers consistently.
- **`index.ts`**: barrel now re-exports `createRedisCsrfStore` and the three auth rate-limit factories. Previously only reachable via subpath.

Build + docs

- **`tsconfig.test.json`**: added so `pnpm typecheck` covers tests as well as `src/`.
- **`package.json`**: `zod` moved into `peerDependenciesMeta.optional: true`. Aligns with the package's actual runtime behavior - consumers who don't import `@goobits/security/validation` don't need zod.
- **`package.json`**: removed `jsonwebtoken` (and `@types/jsonwebtoken`) entirely; added `jose` to runtime deps.
- **`_internal/env.ts`** (new): shared `readEnv()` + `isProduction()` helpers. Replaces four duplicated `globalThis as unknown as { process? }` shims across modules.
- **README**: per-module runtime compatibility table; fixed `import.meta.env.PROD` example (was Vite-only); documented `withAudit` fire-and-forget semantics; documented `cookieOptions` replace-not-merge; documented `getClientIP` no-default-trust policy; added explicit Zod v4 syntax callouts.
- Added vitest suites for previously-untested modules: `recaptcha`, `audit`, `alerting`, `logger`, `rate-limit/auth`, `_internal/cookies`.

### Release notes

First standalone-package release. The bump to v2 reflects breaking API changes vs the legacy internal `v1.x`; everything below is the v2 surface.

### Added

- ESM-only TypeScript-native package with full `.d.ts` declarations
- Subpath exports for every capability (`csrf`, `csrf-redis`, `csp`, `recaptcha`, `validation`, `rate-limit`, `rate-limit/auth`, `rate-limit/sveltekit`, `admin-auth`, `audit`, `audit/sveltekit`, `alerting`, `logger`). Framework-agnostic primitives live at the parent subpaths; SvelteKit-specific adapters live under dedicated `/sveltekit` subpaths so non-SvelteKit consumers never pay for the `@sveltejs/kit` types.
- Pluggable `Logger` interface - every module accepts `logger?: Logger` and is silent by default; bring Pino/Winston/console as needed
- `createCsrf()` factory returning a `CsrfProtection` with `generate`/`setCookie`/`validate`/`cleanup`/`clear`
- `createCspDirectives()` + `buildCsp()` - fully parameterized CSP builder (no hardcoded vendor allowlist; `extraSources` is now caller-supplied)
- `createCspNonce()` for per-request nonce generation
- `verifyRecaptcha()` returns a discriminated-union `RecaptchaResult` with explicit `reason` codes
- `createRateLimiter()` with multi-window sliding-counter support; pluggable `RateLimitStore`
- `createRateLimitHandle()` SvelteKit Handle helper (at `@goobits/security/rate-limit/sveltekit`)
- Pre-baked `createLoginRateLimiter` / `createRegistrationRateLimiter` / `createPasswordResetRateLimiter` factories
- `createAdminAuth()` with JWT + API key fallback (constant-time comparison)
- `generateAdminApiKey()` returns a 256-bit hex API key
- `createAuditLogger()` (framework-agnostic) + `withAudit()` SvelteKit handler wrapper (at `@goobits/security/audit/sveltekit`) for structured event emission with pluggable sinks
- `createSecurityAlerter()` + `createWebhookChannel()` for rule-based dispatch
- Comprehensive test suite (vitest) covering CSRF, CSP, rate-limit, validation, admin-auth

### Changed (breaking from internal v1.x)

- All source files converted from JavaScript to TypeScript with strict typing throughout
- Replaced direct `@goobits/logger` dependency with a pluggable `Logger` interface - package now has zero hard logging dep
- Bumped `zod` peer dep from `^3.x` to `^4.x`; validation helpers updated for v4 API (`safeParseAsync`, `issues`, `z.email()`)
- CSP builder no longer ships an opinionated vendor allowlist; consumers must pass `extraSources` for any vendor URLs they need (Stripe, fonts, CDNs, dev domains)
- Rate limiter API redesigned around a `windows: [{ name, windowMs, maxEvents }]` config (replacing the fixed short/medium/long windows in v1.x)
- `verifyRecaptcha()` now returns `RecaptchaResult` (discriminated union) instead of a plain boolean
- Cookie + header parsing moved to internal helpers; no external dependency on `cookie` or `set-cookie-parser`
- Minimum Node version is now 22 (was 18)

### Removed

- Internal migration docs (`RATE_LIMITER_MIGRATION.md`, `REDIS_RATE_LIMITER_QUICK_START.md`) - these were specific to the source repo's internal cutover, not relevant to standalone consumers
- Opinionated default vendor allowlist from CSP (Stripe paths, MapLibre CDN, local development domains) - consumers now supply these via `extraSources`
- Hard dependency on `@sveltejs/kit` runtime - now an optional peer (CSRF/CSP/recaptcha/rate-limit work in any Fetch-API environment)
- Hard dependency on `ioredis` - now an optional peer (only required when using `csrf-redis` or a Redis rate-limit store)
- Hard dependency on `jsonwebtoken` - replaced with `jose` as the package's only runtime dependency

### Security

- Verified clean: no hardcoded secrets, no embedded credentials, no project-specific paths in source
- All cryptographic primitives use Web Crypto from `globalThis.crypto`; no Node-only `crypto` imports
- Constant-time comparison preserved for CSRF + admin API key
- Default cookie options: `HttpOnly`, `SameSite=Lax`, `Secure` in production
