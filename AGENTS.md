# `@goobits/security` Agent Guide

Server-side security primitives for SvelteKit (and any modern Fetch-API runtime). Notes here describe code that agents/contributors should follow when modifying this package.

---

## Quick reference

- **Category:** library (ESM-only, TypeScript)
- **Distribution:** git submodules consume `.ts` source directly inside first-party workspaces. Published tarballs use compiled ESM and declarations from `dist/`.
- **Primary stack:** TypeScript 6 + Vitest 4. Runtime dependency: `jose ^6`. Optional peer dependencies: `@sveltejs/kit ^2`, `zod ^4`
- **Runtime targets:** Node 22+, Bun, Deno, Cloudflare Workers (anything with Web Crypto on `globalThis`)
- **Engines:** Node `>=22`

## Commands

```bash
pnpm install
pnpm typecheck      # tsc --noEmit (src + tests)
pnpm test           # vitest run
pnpm build          # compile the publish-only dist artifact
pnpm verify:package # install the tarball and import every public entrypoint
pnpm test:watch     # vitest
pnpm test:coverage  # vitest run --coverage
```

## Architecture

```
src/
├── _internal/        # cookie, crypto, logger helpers; never exported
├── crypto/           # encoding, HMAC, AES-GCM/keyrings, signed proofs
├── identity/         # DID-WBA, HTTP signatures, verified principals
├── rate-limit/
│   ├── index.ts      # createRateLimiter + MemoryRateLimitStore (framework-agnostic)
│   └── sveltekit.ts  # createRateLimitHandle (SvelteKit Handle adapter)
├── csrf/
│   └── sveltekit.ts  # bounded stateless double-submit adapter for SvelteKit
├── audit/
│   ├── d1.ts         # durable D1 audit sink
│   └── sveltekit.ts  # request audit adapter
├── validation/
│   ├── simple.ts     # dependency-free boundary validators
│   └── sveltekit.ts  # Zod-backed SvelteKit adapter
├── adminAuth.ts      # admin-only adapter over generic principal auth
├── alerting.ts       # channels, rules, shared threshold observer
├── audit.ts          # framework-agnostic audit logger
├── csp.ts            # parameterized CSP builder
├── csrf.ts           # double-submit CSRF + pluggable store
├── csrfClient.ts     # browser request integration
├── csrfRedis.ts      # structural Redis CSRF store adapter
├── httpCredentials.ts # bounded Basic/Bearer/API-key parsing and verification
├── logger.ts         # pluggable logger contract and implementations
├── principalAuth.ts  # generic JWT/API-key principal authentication
├── recaptcha.ts      # Google v2/v3 verifier
├── redaction.ts      # secret-safe public/audit projections
├── requestBody.ts    # bounded Fetch request-body readers
├── requestOrigin.ts  # Fetch Metadata + Origin/Referer verification
├── runtime.ts        # production-safe cross-runtime environment decisions
├── turnstile.ts      # Cloudflare Turnstile verifier
├── validation.ts     # framework-agnostic Zod helpers
└── index.ts          # curated framework-agnostic root barrel
```

SvelteKit-specific adapters live under `*/sveltekit.ts` subpaths so non-SvelteKit consumers never pay the `@sveltejs/kit` types cost.

`package.json#exports` points directly at `./src/*.ts` for workspace consumers. `publishConfig` rewrites the packed manifest to `./dist/*.js` plus matching declarations; `pnpm verify:package` proves the isolated artifact before release.

Every public factory accepts a `logger?: Logger` and defaults to `noopLogger`. The package has zero hard dependency on any specific logging library.

## Code style

- Tabs, single quotes, no semicolons
- Strict TypeScript (`tsconfig.json` enables `noUncheckedIndexedAccess`, `noUnusedLocals`, etc.)
- All exports named; no default exports
- Use the `_internal/` directory for any helper that should NOT appear in the public API

## Security rules (do not bypass)

- Never log raw tokens, passwords, JWTs, or API keys. The supplied `Logger` may be third-party - assume it captures everything passed to it.
- All cryptographic comparisons MUST be constant-time. Public modules use
  `constantTimeEqual()` from `crypto/encoding`; private byte-level primitives
  may use `timingSafeEqualBytes()` from `_internal/crypto.ts`.
- All random values for tokens/keys MUST come from `globalThis.crypto.getRandomValues` (via `getRandomBytes`). Never use `Math.random()` for security-sensitive paths.
- `csp.ts` MUST NOT hardcode any third-party vendor URLs (Stripe, fonts, CDNs, etc.). Consumers supply those via `extraSources`. Adding vendor knowledge to defaults would force every consumer to inherit those policies whether they need them or not.
- When this package's deps change in `package.json`, verify their licenses remain permissive (MIT / Apache 2.0 / BSD). No GPL-ish copyleft deps.

## Project-specific overrides

- **`@goobits/logger` is intentionally not a dependency.** Use the local pluggable `Logger` interface from `./logger.js`. If a future module needs richer structured logging, add it via the consumer-supplied logger - don't reach for a specific logging library.
- **`jose ^6` is the package's only direct runtime dependency.** Used by principal and admin authentication for cross-runtime JWTs (Web Crypto-based; works on Node, Bun, Deno, and Cloudflare Workers). Do NOT add `jsonwebtoken` back - it's CJS-only and would re-break the cross-runtime claim.
- **Zod is an optional peer dep at `^4.0.0`.** When updating validation code, use v4 APIs (`safeParseAsync`, `z.email()`, the `issues` shape on errors).
- **`@sveltejs/kit` and `zod` are optional peers.** Consumers install only the adapter dependencies they use.
- **The Redis CSRF adapter does not own a Redis client dependency.** Hosts pass any client satisfying the exported `RedisLike` contract; `ioredis` is one possible host-owned implementation.

## Where to look

- Public API barrel: `src/index.ts`
- Per-capability module: `src/<name>.ts` or `src/<name>/<sub>.ts`
- Tests for each module: `__tests__/<name>.test.ts`
- Test config: `vitest.config.ts`
- Types-strict config: `tsconfig.json`

## Definition of Done

- `pnpm typecheck` passes with no errors (covers `src/` and `tests/`)
- `pnpm test` passes with no failing assertions
- `pnpm verify:package` passes from a clean packed consumer
- Every entry in `package.json#exports` points at an existing `src/*.ts` file
- Every entry in `package.json#publishConfig.exports` points at compiled JavaScript and declarations
- No generated `dist/`, `node_modules/`, `.DS_Store`, or `*.tsbuildinfo` tracked
- README + CHANGELOG updated for any user-facing change
- New deps reviewed for license compatibility (permissive only)

## Shared-Folder Git

- Shared macOS/Linux checkouts should use `core.filemode=false`; chmod-only changes will not be noticed reliably.
- When a script must be executable, run `git update-index --chmod=+x path/to/script.sh` and include that in the commit.
