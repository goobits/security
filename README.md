# @goobits/security

Server-side security primitives for modern JavaScript runtimes, with SvelteKit adapters where framework integration is useful. CSRF protection, rate limiting, reCAPTCHA verification, CSP headers, request validation, admin auth, audit logging, and security alerting, all in one TypeScript-native package with minimal runtime dependencies.

## TL;DR

- Add as a pnpm workspace git submodule; your bundler compiles the TypeScript source directly.
- Import only the subpaths you need: `csrf`, `rate-limit`, `recaptcha`, `csp`, `validation`, `principal-auth`, `admin-auth`, `audit`, `alerting`, `crypto`, `identity`.
- Pass a `Logger` to any factory for structured log output; omit it for silent operation.
- All crypto uses Web Crypto from `globalThis` and runs on Node 22+, Bun, Deno, and Cloudflare Workers.

## Highlights

- **CSRF:** double-submit cookie pattern with timing-safe comparison, pluggable token store (in-memory or Redis)
- **Rate limiting:** sliding-window counter with multi-window support, pluggable store
- **reCAPTCHA:** Google v2 + v3 verification with score thresholds, returns a discriminated-union result
- **Content Security Policy:** generic builder; pass your vendor allowlist as config, no hardcoded knowledge of Stripe/Cloudflare/etc.
- **Validation:** Zod v4 middleware for request body / query / params
- **Principal authentication:** generic JWT bearer + API key principal authentication
- **Admin authentication:** JWT bearer + API key fallback with constant-time comparison
- **Crypto:** Web Crypto encoding, HMAC, AES-GCM, SHA-256, and deterministic proof helpers
- **Identity:** DID-WBA and HTTP Signature request identity adapters
- **Audit logging:** structured events with pluggable sinks (database, cloud logger, anywhere)
- **Alerting:** rule-based dispatch to webhooks (Slack, PagerDuty, etc.) on critical events
- **Minimal forced dependencies:** uses Web Crypto from `globalThis`; `jose` is the only runtime dependency, with optional peer deps for SvelteKit, ioredis, and zod
- **Pluggable logger:** every module accepts a `Logger` interface; bring your own (Pino, Winston, console, or silent)
- **ESM-only, full TypeScript:** subpath exports for treeshaking; runs on Node 22+, Bun, Deno, Cloudflare Workers

## Usage

`@goobits/security` is distributed as a **git submodule with TypeScript source**: no build step, no `dist/`, no npm package. Consume it from a workspace whose bundler (Vite, esbuild, SvelteKit, Bun, Deno, etc.) handles `.ts` natively.

### Why source-only?

We share this package across several internal SvelteKit consumers. Every consumer's bundler already compiles `.ts` end-to-end, so shipping a pre-built `dist/` adds a build/version-dance step that buys nothing. Source-level distribution keeps fixes one diff away in either direction, and the consumer's existing typecheck/test pipeline sees real types through the boundary rather than `.d.ts` reconstructions.

If you need a non-bundler runtime (raw Node, a third-party consumer, etc.), the trade-off matters; this package is intentionally not designed for those cases.

### pnpm workspace (recommended)

```bash
# from your consumer repo root:
git submodule add git@github.com:goobits/security.git packages/security
```

```yaml
# pnpm-workspace.yaml
packages:
  - apps/*
  - packages/*
```

```jsonc
// your app's package.json
"dependencies": {
  "@goobits/security": "workspace:*",
  "jose": "^5.9.6"
}
```

```bash
pnpm install

# Optional peer dependencies — install only what you use:
pnpm add @sveltejs/kit   # if using SvelteKit helper subpaths
pnpm add ioredis         # if using Redis-backed CSRF
pnpm add zod             # if using validation
```

### npm / yarn / Bun workspaces

The same submodule layout works. Just declare the workspace in the format your package manager expects:

- **npm** / **yarn v1+**: add `"workspaces": ["packages/*", "apps/*"]` to your root `package.json` and reference the package as `"@goobits/security": "*"` from a workspace member.
- **Bun**: same as npm.
- **No workspace at all**: declare a `file:` reference, e.g. `"@goobits/security": "file:./packages/security"`.

`@goobits/security` depends on [`jose`](https://github.com/panva/jose) for JWT operations in `admin-auth` (Web Crypto-based; cross-runtime). No other transitive runtime deps.

### Pinning a version

`workspace:*` always tracks the submodule's current HEAD. For production you should pin the submodule to a specific commit. Two options:

```bash
# Pin to a tag (recommended for releases):
cd packages/security && git checkout v2.0.0 && cd ../..
git add packages/security && git commit -m "chore: pin @goobits/security to v2.0.0"

# Or pin to a specific commit SHA:
cd packages/security && git checkout <sha> && cd ../..
git add packages/security && git commit
```

The submodule's recorded SHA in your consumer repo becomes the pinned version. Future `git submodule update --remote` runs are explicit opt-in.

### Syncing from upstream

```bash
git submodule update --remote packages/security
git add packages/security && git commit -m "chore: bump @goobits/security"
```

## At a glance

```ts
import { createCsrf } from '@goobits/security/csrf'
import { buildCsp } from '@goobits/security/csp'
import { createRateLimiter } from '@goobits/security/rate-limit'
import { verifyRecaptcha } from '@goobits/security/recaptcha'
import { getInputValidator } from '@goobits/security/validation'
import { withValidation } from '@goobits/security/validation/sveltekit'
import { createPrincipalAuth } from '@goobits/security/principal-auth'
import { createAdminAuth } from '@goobits/security/admin-auth'
import { createAuditLogger } from '@goobits/security/audit'
import { withAudit } from '@goobits/security/audit/sveltekit'
import { createSecurityAlerter, createWebhookChannel } from '@goobits/security/alerting'
import { createSecurityProof, sealJson, verifySecurityProof } from '@goobits/security/crypto'
import { verifyDidWbaIdentity } from '@goobits/security/identity'
```

Each module is independently importable. Import only what you need.

---

## Identity

```ts
import { verifyDidWbaIdentity } from '@goobits/security/identity'

const result = await verifyDidWbaIdentity({
  header: request.headers.get('authorization'),
  expectedDomain: 'example.com',
  verifySignature: async ({ did, verificationMethod, message, signature }) => {
    const key = await resolvePublicKey(did, verificationMethod)
    return verifyWithYourProtocolKey(key, message, signature)
  }
})
```

Identity adapters answer "which decentralized principal signed this request?" They do not fetch DID documents, store nonces, or grant product permissions by themselves. Consumers provide key resolution, replay storage, and resource authorization.

---

## Principal auth

```ts
import { createPrincipalAuth } from '@goobits/security/principal-auth'

const auth = createPrincipalAuth({
  jwtSecret: process.env.JWT_SECRET!,
  audience: 'my-app',
  issuer: 'my-auth-service',
  apiKeys: [
    { key: process.env.SERVICE_API_KEY!, principal: { id: 'service-a', roles: ['service'] } }
  ]
})

const result = await auth.requirePrincipal(request)
if (!result.authenticated) {
  return new Response('Unauthorized', { status: 401 })
}

// result.principal is the authenticated caller.
// Resource authorization belongs in your app's permission system.
```

`principal-auth` answers "who is calling?" only. It intentionally does not decide whether that principal may edit a resource, manage a space, run a tool, or read private data.

`admin-auth` remains available as a focused admin-route adapter and delegates to
the same underlying principal-auth implementation.

---

## Crypto

```ts
import {
  createSecurityProof,
  randomHex,
  sealJson,
  verifySecurityProof
} from '@goobits/security/crypto'

const key = randomHex(32)
const sealed = await sealJson({ refreshToken: 'secret' }, { key })

const proof = await createSecurityProof({ id: 'message-1' }, {
  secret: process.env.PROOF_SECRET!,
  verificationMethod: 'hmac:app',
  domain: 'example.com',
  challenge: 'nonce-123'
})

const result = await verifySecurityProof({ id: 'message-1' }, proof, {
  secret: process.env.PROOF_SECRET!,
  domain: 'example.com',
  challenge: 'nonce-123'
})
```

The `crypto` subpath is framework-agnostic. It provides encoding helpers, random bytes/hex, SHA-256, HMAC signatures, AES-GCM sealing/opening, and deterministic `SecurityProof` envelopes. Product permissions, roles, and app-specific authorization remain outside this package.

Narrow imports are also available: `@goobits/security/crypto/encoding`, `@goobits/security/crypto/signatures`, `@goobits/security/crypto/aead`, and `@goobits/security/crypto/proof`.

---

## CSRF

```ts
import { createCsrf } from '@goobits/security/csrf'

const csrf = createCsrf()

// In a page load or hook:
const response = await resolve(event)
const token = await csrf.generate()
csrf.setCookie(response, token)
return response

// In a form action:
if (!(await csrf.validate(event.request))) {
  return new Response('Invalid CSRF token', { status: 403 })
}
```

**Multi-instance deployment?** Swap the in-memory store for a Redis one:

```ts
import Redis from 'ioredis'
import { createCsrf } from '@goobits/security/csrf'
import { createRedisCsrfStore } from '@goobits/security/csrf-redis'

const client = new Redis(process.env.REDIS_URL!)
const csrf = createCsrf({
  tokenStore: createRedisCsrfStore({ client })
})
```

The returned `CsrfProtection` object also exposes `getToken(request)`, `cleanup()` (for the in-memory store; periodically drops expired tokens), `clear()` (purges the store), and `storeSize` (debug-only). For long-running processes with the default in-memory store, schedule `csrf.cleanup()` on a 5-minute interval. Redis stores handle expiry via TTL with no manual cleanup needed.

⚠️ **`cookieOptions` replaces defaults, doesn't merge.** If you supply your own `cookieOptions`, you also lose the sensible defaults (`HttpOnly`, `SameSite=Lax`, etc.). Copy the defaults first if you only want to tweak one field.

### `failClosed`: for compliance-sensitive routes

Default behavior on store errors (Redis down, etc.) is **fail-open**: `validate()` will still let requests through if the cookie + header constant-time compare succeeds. For routes where availability is less important than correctness, opt into fail-closed:

```ts
const csrf = createCsrf({ failClosed: true })

// On a route that explicitly checks expiration:
if (!(await csrf.validate(event.request, { checkExpiry: true }))) {
  return new Response('CSRF validation failed', { status: 403 })
}
```

ℹ️ **Scope**: `failClosed` is consulted inside the expiry-check path (`isTokenExpired`). It takes effect when you pass `{ checkExpiry: true }` to `validate()`. Without `checkExpiry`, the store isn't queried at all so `failClosed` has nothing to gate.

### `disabled`: tests only

Set via `DISABLE_CSRF=true` env var or `createCsrf({ disabled: true })`. `createCsrf()` **throws synchronously** if either is set when `NODE_ENV === 'production'`, failing loud and never silently disabled in prod.

### `serializeCookie` rejects illegal characters

The package validates cookie name + value at write time against RFC 6265's allowed character class. Any cookie value containing CRLF, `;`, `,`, `"`, `\`, or whitespace throws synchronously. This is automatic, requiring no action on your part, but it does mean a future custom `cookieOptions` change is constrained to the RFC-legal set.

## CSP

```ts
import { buildCsp } from '@goobits/security/csp'

const isProd = process.env.NODE_ENV === 'production'
// In SvelteKit/Vite, use `import.meta.env.PROD` instead.

response.headers.set('Content-Security-Policy', buildCsp({
  mode: isProd ? 'production' : 'development',
  nonce: locals.cspNonce,
  extraSources: {
    'script-src': ['https://js.stripe.com'],
    'connect-src': ['https://api.stripe.com'],
    'img-src':    ['https://cdn.example.com', 'data:']
  }
}))
```

The package has no hardcoded vendor list. You supply your own `extraSources`.

## Rate limiting

```ts
import { createRateLimiter } from '@goobits/security/rate-limit'
import { createRateLimitHandle } from '@goobits/security/rate-limit/sveltekit'

const limiter = createRateLimiter({
  windows: [
    { name: 'burst', windowMs:    60_000, maxEvents:  5 },
    { name: 'hour',  windowMs: 3_600_000, maxEvents: 60 }
  ]
})

// As a SvelteKit Handle:
export const handle = createRateLimitHandle({
  limiter,
  identifier: (event) => event.getClientAddress()
})

// Or imperatively:
const verdict = await limiter.check(clientId)
if (!verdict.allowed) {
  return new Response('Too Many Requests', {
    status: 429,
    headers: { 'Retry-After': String(verdict.retryAfterSec) }
  })
}
```

⚠️ **Multi-instance deployment?** The default `MemoryRateLimitStore` keeps counters per-process. Each replica enforces an independent budget, so a 5-pod deployment effectively allows `5 × maxEvents`. Use a Redis-backed `RateLimitStore` implementation for multi-pod prod environments. The package provides `RateLimitStore` as the interface; you implement (or wrap an `ioredis` client) yourself for now.

⚠️ **`getClientIP` trusts NO proxy headers by default.** This is intentional: blindly trusting `x-forwarded-for` lets attackers spoof the identifier. To enable header trust:

```ts
import { getClientIP } from '@goobits/security/rate-limit'

// Cloudflare:
const ip = getClientIP(event.request, { trustHeaders: ['cf-connecting-ip'] })

// AWS ALB / GCP LB (configured to strip client-supplied XFF):
const ip = getClientIP(event.request, { trustHeaders: ['x-forwarded-for'] })
```

In SvelteKit, prefer `event.getClientAddress()`, which honors your platform adapter's trusted-proxy config.

Pre-baked auth flow limiters (login, registration, password reset) live in `@goobits/security/rate-limit/auth`:

```ts
import {
  createLoginRateLimiter,
  createRegistrationRateLimiter,
  createPasswordResetRateLimiter
} from '@goobits/security/rate-limit/auth'

const loginLimiter        = createLoginRateLimiter()         // 5/min, 15/15min
const registrationLimiter = createRegistrationRateLimiter()  // 3/10min, 5/hour
const passwordResetLimiter = createPasswordResetRateLimiter() // 3/15min, 5/hour
```

Each factory takes the same `{ store?, logger?, keyPrefix? }` options as `createRateLimiter`; use a shared `RateLimitStore` (e.g. Redis) to make all three limiters multi-instance safe at once.

Custom in-memory store config (e.g. tuning the cleanup probability):

```ts
import { MemoryRateLimitStore, createRateLimiter } from '@goobits/security/rate-limit'

const store = new MemoryRateLimitStore({ cleanupProbability: 0.05 }) // 5% per increment
const limiter = createRateLimiter({ windows: [...], store })
```

## reCAPTCHA

```ts
import { verifyRecaptcha } from '@goobits/security/recaptcha'

const result = await verifyRecaptcha(token, {
  action: 'submit_contact_form',
  minScore: 0.7
})

if (!result.success) {
  console.error('reCAPTCHA failed:', result.reason)
  return new Response('Captcha failed', { status: 400 })
}
console.log('Score:', result.score)
```

⚠️ **`allowInDevelopment` defaults to `false`.** If you want the dev-bypass (verification passes when `RECAPTCHA_SECRET_KEY` is missing AND `NODE_ENV !== 'production'`), opt in explicitly:

```ts
const result = await verifyRecaptcha(token, { allowInDevelopment: true })
```

This safer default ensures runtimes that don't set `NODE_ENV` (Cloudflare Workers, Deno, CI) never silently disable CAPTCHA.

### Network timeout

`verifyRecaptcha` aborts the call to Google after `timeoutMs` (default `5000`). Tune as needed:

```ts
const result = await verifyRecaptcha(token, { timeoutMs: 2000 })
// timeout returns: { success: false, reason: 'api-error' }
```

## Validation (Zod v4)

```ts
import { z } from 'zod'
import { withValidation } from '@goobits/security/validation/sveltekit'

export const POST = withValidation(
  {
    body: z.object({ email: z.email(), name: z.string().min(1) }),  // Zod v4 syntax
    query: z.object({ source: z.string().optional() })
  },
  async (event) => {
    const { body, query } = event.locals.validatedData
    // ...
    return new Response('OK')
  }
)
```

Standalone validator (returns `{ success, data | issues }` without wrapping a handler):

```ts
import { getInputValidator } from '@goobits/security/validation'

const validate = getInputValidator(z.object({ email: z.email() }))
const result = validate({ email: 'a@b.com' })
if (result.success) {
  console.log(result.data.email)
} else {
  console.error(result.issues)
}
```

Note: `@goobits/security` peer-depends on `zod ^4.0.0` (optional). If you don't import `@goobits/security/validation` or `@goobits/security/validation/sveltekit` you don't need zod installed. The SvelteKit middleware also requires `@sveltejs/kit`.

## Admin auth

```ts
import { createAdminAuth, generateAdminApiKey } from '@goobits/security/admin-auth'

const adminAuth = createAdminAuth({
  jwtSecret: process.env.JWT_SECRET!,   // >= 32 chars — throws otherwise
  apiKey:    process.env.ADMIN_API_KEY, // optional fallback
  algorithms: ['HS256'],                // default: ['HS256'] (pinned tight)
  audience:  'my-app',                  // optional — rejected if token aud differs
  issuer:    'my-auth-service',         // optional — rejected if token iss differs
  clockTolerance: 30                    // optional — seconds of skew tolerated on exp/nbf
})

export async function POST({ request }) {
  const result = await adminAuth.requireAdmin(request)
  if (!result.authenticated) {
    return new Response('Unauthorized', { status: 401 })
  }
  // result.user.id, result.method ('jwt' | 'apikey')
}

// Issue a new token (NOTE: async since the v2.0.0 jose swap):
const token = await adminAuth.createAdminToken({ id: 'user-1', role: 'admin' })

// Numeric tokenTtl is RELATIVE seconds (1 hour below), NOT absolute UNIX time:
const shortToken = await adminAuth.createAdminToken({ id: 'u1', role: 'admin' }, 3600)

// Generate a fresh API key (256-bit, hex-encoded) — store this once at
// provisioning time in your secret manager; do not regenerate per request:
const key = generateAdminApiKey()
```

⚠️ **`jwtSecret` must be ≥32 characters.** `createAdminAuth()` throws at construction time on shorter secrets. Use a cryptographically random secret.

⚠️ **`algorithms` defaults to `['HS256']`.** Pin tight. Adding `HS384`/`HS512` is fine; mixing in `none` is impossible (the type forbids it).

## Audit logging

`withAudit` derives `outcome` automatically from the handler's response:
2xx-3xx → `success`, 401/403 → `denied`, thrown → `error`, otherwise → `failure`.
It dispatches **fire-and-forget**: the audit event is sent without awaiting
the sink, so the user sees the response before the audit lands. For
compliance contexts that require the audit record durably stored before
returning, call `auditor.log()` explicitly with `await` instead.

```ts
import { createAuditLogger } from '@goobits/security/audit'
import { withAudit } from '@goobits/security/audit/sveltekit'

const auditor = createAuditLogger({
  sink: {
    async record(event) {
      await db.insert('audit_log').values(event)
    }
  }
})

// Wrap a handler:
export const POST = withAudit(
  { action: 'admin.delete-user', auditor, actorId: (e) => e.locals.user?.id },
  async (event) => {
    // ... your logic ...
    return new Response('OK')
  }
)

// Capture the request body (e.g. for a contact form audit) with redaction:
export const POST = withAudit(
  {
    action: 'contact.submit',
    auditor,
    includeRequestBody: true,
    // Defaults: ['password', 'token', 'secret', 'apiKey', 'authorization',
    // 'creditCard', 'cvv']. Override with your own set (case-insensitive,
    // recurses into nested objects and arrays). Pass `redactKeys: []` to
    // disable redaction entirely (NOT recommended for routes with credentials).
    redactKeys: ['password', 'token', 'creditCard', 'ssn']
  },
  async (event) => { /* ... */ return new Response('OK') }
)

// Or call directly:
await auditor.log({
  action: 'user.login',
  outcome: 'success',
  actorId: user.id
})
```

## Alerting

```ts
import { createSecurityAlerter, createWebhookChannel } from '@goobits/security/alerting'

const slack = createWebhookChannel({
  url: process.env.SLACK_WEBHOOK_URL!,
  transform: (a) => ({
    text: `*[${ a.severity.toUpperCase() }]* ${ a.title }\n${ a.message }`
  })
})

const alerter = createSecurityAlerter({
  channels: [ slack ],
  rules: [
    // Alert on any admin-route denial:
    (event) => event.action.startsWith('admin.') && event.outcome === 'denied'
      ? {
          severity: 'critical',
          title: 'Admin access denied',
          message: event.action,
          source: 'goobits/security',
          timestamp: event.timestamp,
          context: { actorId: event.actorId, clientIp: event.clientIp }
        }
      : null
  ]
})

// Plug into the audit sink:
const auditor = createAuditLogger({
  sink: {
    async record(event) {
      await db.insert('audit_log').values(event)
      await alerter.process(event)
    }
  }
})
```

## Pluggable logger

Every factory accepts an optional `Logger`. By default they're silent:

```ts
import { createConsoleLogger } from '@goobits/security/logger'

const log = createConsoleLogger({ prefix: '[my-app]', level: 'debug' })

const csrf = createCsrf({ logger: log })
```

Any object implementing `{ debug, info, warn, error }` works, including Pino, Winston, or `console`.

---

## Runtime + environment

- **Node** ≥22 (for native Web Crypto on `globalThis.crypto`)
- **Bun**, **Deno**, **Cloudflare Workers**: supported with caveats (see table below)
- ESM only: `"type": "module"` consumers required

### Per-module runtime compatibility

| Module | Node ≥22 | Bun | Deno | Cloudflare Workers |
|---|---|---|---|---|
| `csrf` | ✅ | ✅ | ✅ | ✅ |
| `csrf-redis` | ✅ | ✅ | requires `ioredis` polyfill | ❌ (no TCP from Workers) |
| `csp` | ✅ | ✅ | ✅ | ✅ |
| `recaptcha` | ✅ | ✅ | ✅ | ✅ |
| `crypto` | ✅ | ✅ | ✅ | ✅ |
| `identity` | ✅ | ✅ | ✅ | ✅ |
| `validation` † | ✅ | ✅ | ✅ | ✅ |
| `rate-limit` | ✅ | ✅ | ✅ | ✅ |
| `rate-limit/auth` | ✅ | ✅ | ✅ | ✅ |
| `rate-limit/sveltekit` † | ✅ | ✅ | ✅ | ✅ |
| `principal-auth` | ✅ | ✅ | ✅ | ✅ (uses `jose`, Web Crypto-based) |
| `admin-auth` | ✅ | ✅ | ✅ | ✅ (uses `jose`, Web Crypto-based) |
| `audit` | ✅ | ✅ | ✅ | ✅ |
| `audit/sveltekit` † | ✅ | ✅ | ✅ | ✅ |
| `alerting` | ✅ | ✅ | ✅ | ✅ |
| `logger` | ✅ | ✅ | ✅ | ✅ |

† SvelteKit adapter: types reference `@sveltejs/kit`. Use the parent subpath (`validation`'s `getInputValidator`, `rate-limit`'s `createRateLimiter`, `audit`'s `createAuditLogger`) directly for framework-agnostic usage.

All modules use the Web Crypto API on `globalThis.crypto` for randomness and signing. None import from `node:crypto`, `node:buffer`, or any other Node-only built-ins.

> Continuous integration exercises Node 22. Bun, Deno, and Cloudflare Workers are validated manually; if you hit a runtime-specific issue, please open an issue with the runtime version and a minimal repro.

### Required env vars (when used)

| Module | Variable | Required? |
|---|---|---|
| `recaptcha` | `RECAPTCHA_SECRET_KEY` | Yes (or pass `secretKey` via options) |
| `admin-auth` | (none; `jwtSecret` passed via config) | n/a |
| `csrf` | `DISABLE_CSRF=true` | Tests only; **throws at startup if set in production** |
| `csrf` | `NODE_ENV=production` | Read for cookie `Secure` flag default |
| `recaptcha` | `NODE_ENV` | Read to gate `allowInDevelopment` (default off) |

The package never reads env vars except via these explicit fallbacks. **Best practice**: pass secrets explicitly via config and don't rely on env-var fallbacks in production code.

---

## License

MIT. See [LICENSE](./LICENSE).
