# `@goobits/security` Agent Guide

Server-side security primitives for SvelteKit (and any modern Fetch-API runtime). Notes here describe code that agents/contributors should follow when modifying this package.

---

## Quick reference

- **Category:** library (ESM-only, TypeScript)
- **Distribution:** git submodule consumed inside a pnpm workspace. Consumer bundlers (Vite/esbuild/SvelteKit) compile the `.ts` source directly — no build step, no `dist/`, no npm publish.
- **Primary stack:** TypeScript 5.9 + vitest. Runtime dep: `jose ^5`. Optional peer-deps: `@sveltejs/kit ^2`, `zod ^4`, `ioredis ^5`
- **Runtime targets:** Node 22+, Bun, Deno, Cloudflare Workers (anything with Web Crypto on `globalThis`)
- **Engines:** Node `>=22`

## Commands

```bash
pnpm install
pnpm typecheck      # tsc --noEmit (src + tests)
pnpm test           # vitest run
pnpm test:watch     # vitest
pnpm test:coverage  # vitest run --coverage
```

## Architecture

```
src/
├── _internal/        # crypto + cookie + env + body helpers; NOT exported
├── rate-limit/
│   ├── index.ts      # createRateLimiter + MemoryRateLimitStore (framework-agnostic)
│   ├── auth.ts       # pre-baked auth-endpoint factories
│   └── sveltekit.ts  # createRateLimitHandle (SvelteKit Handle adapter)
├── audit/
│   └── sveltekit.ts  # withAudit handler wrapper (SvelteKit adapter)
├── csrf.ts           # double-submit CSRF, pluggable token store
├── csrf-redis.ts     # Redis adapter for the CSRF token store
├── csp.ts            # parameterized CSP builder (no hardcoded vendors)
├── recaptcha.ts      # Google v2/v3 verifier (discriminated-union result)
├── validation.ts     # Zod v4 helpers (framework-agnostic)
├── validation/
│   └── sveltekit.ts  # withValidation SvelteKit adapter
├── admin-auth.ts     # JWT + API key admin gate
├── audit.ts          # createAuditLogger + sinks (framework-agnostic)
├── alerting.ts       # rule-based dispatch over pluggable channels
├── logger.ts         # pluggable Logger interface + noopLogger + createConsoleLogger
└── index.ts          # barrel re-exporting framework-agnostic surface
```

SvelteKit-specific adapters live under `*/sveltekit.ts` subpaths so non-SvelteKit consumers never pay the `@sveltejs/kit` types cost.

`package.json#exports` points directly at `./src/*.ts`. There is no build step. Consumers' bundlers (Vite/esbuild/SvelteKit) compile the `.ts` source as part of their own pipeline.

Every public factory accepts a `logger?: Logger` and defaults to `noopLogger`. The package has zero hard dependency on any specific logging library.

## Code style

- Tabs, single quotes, no semicolons
- Strict TypeScript (`tsconfig.json` enables `noUncheckedIndexedAccess`, `noUnusedLocals`, etc.)
- All exports named; no default exports
- Use the `_internal/` directory for any helper that should NOT appear in the public API

## Security rules (do not bypass)

- Never log raw tokens, passwords, JWTs, or API keys. The supplied `Logger` may be third-party — assume it captures everything passed to it.
- All cryptographic comparisons MUST be constant-time. Use `timingSafeEqualBytes` from `_internal/crypto.ts`.
- All random values for tokens/keys MUST come from `globalThis.crypto.getRandomValues` (via `getRandomBytes`). Never use `Math.random()` for security-sensitive paths.
- `csp.ts` MUST NOT hardcode any third-party vendor URLs (Stripe, fonts, CDNs, etc.). Consumers supply those via `extraSources`. Adding vendor knowledge to defaults would force every consumer to inherit those policies whether they need them or not.
- When this package's deps change in `package.json`, verify their licenses remain permissive (MIT / Apache 2.0 / BSD). No GPL-ish copyleft deps.

## Project-specific overrides

- **`@goobits/logger` is intentionally not a dependency.** Use the local pluggable `Logger` interface from `./logger.js`. If a future module needs richer structured logging, add it via the consumer-supplied logger — don't reach for a specific logging library.
- **`jose ^5` is the package's only direct runtime dependency.** Used by `admin-auth` for cross-runtime JWT (Web Crypto-based; works on Node, Bun, Deno, and Cloudflare Workers). Do NOT add `jsonwebtoken` back — it's CJS-only and would re-break the cross-runtime claim.
- **Zod is an optional peer dep at `^4.0.0`.** When updating validation code, use v4 APIs (`safeParseAsync`, `z.email()`, the `issues` shape on errors).
- **`ioredis`, `@sveltejs/kit`** are optional peers. Modules that depend on them MUST gracefully no-op (or throw a clear error) when the peer is absent. They are loaded via `import` at module level, so consumers who don't install them simply never import those subpaths.

## Where to look

- Public API barrel: `src/index.ts`
- Per-capability module: `src/<name>.ts` or `src/<name>/<sub>.ts`
- Tests for each module: `tests/<name>.test.ts`
- Test config: `vitest.config.ts`
- Types-strict config: `tsconfig.json`

## Definition of Done

- `pnpm typecheck` passes with no errors (covers `src/` and `tests/`)
- `pnpm test` passes with no failing assertions
- Every entry in `package.json#exports` points at an existing `src/*.ts` file
- No `dist/`, `node_modules/`, `.DS_Store`, or `*.tsbuildinfo` tracked
- README + CHANGELOG updated for any user-facing change
- New deps reviewed for license compatibility (permissive only)
