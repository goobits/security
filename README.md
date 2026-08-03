# @goobits/security

Server-side security primitives for modern JavaScript runtimes, with SvelteKit adapters where framework integration is useful. CSRF protection, rate limiting, reCAPTCHA verification, CSP headers, request validation, admin auth, audit logging, and security alerting, all in one TypeScript-native package with minimal runtime dependencies.

## TL;DR

- Add as a pnpm workspace git submodule for source consumption, or install the published compiled package.
- Import only the subpaths you need: `csrf`, `rate-limit`, `recaptcha`, `csp`, `validation`, `principal-auth`, `admin-auth`, `http-credentials`, `redaction`, `audit`, `alerting`, `crypto`, `identity`.
- Pass a `Logger` to any factory for structured log output; omit it for silent operation.
- All crypto uses Web Crypto from `globalThis` and runs on Node 22+, Bun, Deno, and Cloudflare Workers.

## Highlights

- **CSRF:** double-submit cookie pattern with timing-safe comparison, pluggable token store (in-memory or Redis)
- **Rate limiting:** sliding-window counter with multi-window support, pluggable store
- **Private rate-limit keys:** optional HMAC store wrapper keeps raw identifiers out of backing stores
- **reCAPTCHA:** Google v2 + v3 verification with score thresholds, returns a discriminated-union result
- **Content Security Policy:** generic builder; pass your vendor allowlist as config, no hardcoded knowledge of Stripe/Cloudflare/etc.
- **Validation:** Zod v4 middleware for request body / query / params
- **Request bodies:** bounded cross-runtime readers for bytes, JSON, form data,
  and async byte streams
- **Principal authentication:** generic JWT bearer + API key principal authentication
- **Admin authentication:** JWT bearer + API key fallback with constant-time comparison
- **Crypto:** Web Crypto encoding, HMAC, rotation-ready AES-GCM keyrings,
  bounded-memory incremental SHA-256 and BLAKE3 hashing, and deterministic
  proof helpers
- **HTTP credentials:** strict Basic, Bearer, and API-key parsing plus constant-work password and HMAC API-key verification helpers
- **Redaction:** recursive, cycle-safe structured redaction plus bounded
  credential removal from unstructured diagnostic text before values reach
  logs, audit sinks, or public projections
- **Identity:** DID-WBA and HTTP Signature request identity adapters
- **Audit logging:** structured events with pluggable sinks (database, cloud logger, anywhere)
- **Alerting:** rule-based dispatch to webhooks (Slack, PagerDuty, etc.) on critical events
- **Minimal forced dependencies:** uses Web Crypto from `globalThis`,
  `hash-wasm` for incremental SHA-256 and BLAKE3 hashing, and `jose` for JWTs.
  SvelteKit and Zod remain optional peers, and Redis clients remain host-owned.
- **Pluggable logger:** every module accepts a `Logger` interface; bring your own (Pino, Winston, console, or silent)
- **ESM-only, full TypeScript:** subpath exports for treeshaking; runs on Node 22+, Bun, Deno, Cloudflare Workers

## Usage

`@goobits/security` supports two deliberate distribution modes. First-party workspaces consume TypeScript source directly from a pinned git submodule. Published packages contain compiled ESM and declarations so clean Node installations never execute TypeScript from `node_modules`.

### Why two modes?

Internal SvelteKit consumers already compile `.ts` end-to-end, so source-level workspace exports keep their development loop immediate and typecheck the real source boundary. The publish pipeline rewrites only the packed manifest to compiled `dist/` exports. This preserves the workspace workflow while making the npm artifact safe for runtimes that do not strip dependency TypeScript.

The package verifier installs the generated tarball in an isolated consumer and imports every public entrypoint before release.

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
  "@goobits/security": "workspace:*"
}
```

```bash
pnpm install

# Optional peer dependencies  -  install only what you use:
pnpm add @sveltejs/kit   # if using SvelteKit helper subpaths
pnpm add zod             # if using validation
```

### Published package

```bash
pnpm add @goobits/security
```

Published artifacts contain only compiled output, declarations, the package manifest, and release documentation. `src/`, tests, repository metadata, and release tooling are excluded.

### npm / yarn / Bun workspaces

The same submodule layout works. Just declare the workspace in the format your package manager expects:

- **npm** / **yarn v1+**: add `"workspaces": ["packages/*", "apps/*"]` to your root `package.json` and reference the package as `"@goobits/security": "*"` from a workspace member.
- **Bun**: same as npm.
- **No workspace at all**: declare a `file:` reference, e.g. `"@goobits/security": "file:./packages/security"`.

`@goobits/security` depends on [`jose`](https://github.com/panva/jose) for
cross-runtime JWT operations and `hash-wasm` for incremental SHA-256 and
BLAKE3 hashing. It has no other direct runtime dependencies.

### Pinning a version

`workspace:*` always tracks the submodule's current HEAD. For production you should pin the submodule to a specific commit. Two options:

```bash
# Pin to a tag (recommended for releases):
cd packages/security && git checkout <version-tag> && cd ../..
git add packages/security && git commit -m "chore: pin @goobits/security"

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
import { parseBearerToken, verifyApiKey } from '@goobits/security/http-credentials'
import { redactSecretText, redactSensitive } from '@goobits/security/redaction'
import { createAuditLogger } from '@goobits/security/audit'
import { withAudit } from '@goobits/security/audit/sveltekit'
import { createSecurityAlerter, createWebhookChannel } from '@goobits/security/alerting'
import { createSecurityProof, sealJson, verifySecurityProof } from '@goobits/security/crypto'
import { verifyDidWbaIdentity } from '@goobits/security/identity'
import { signJwt, verifyJwt, verifyJwtWithJwks } from '@goobits/security/jwt'
```

Each module is independently importable. Import only what you need.

---

## JWT

Use the shared JWT primitive when a protocol needs a short-lived,
purpose-bound HMAC token without adopting principal-auth policy:

```ts
import { signJwt, verifyJwt } from '@goobits/security/jwt'

const token = await signJwt(
	{ roomId: 'room-1' },
	{
		secret,
		expiresIn: 60,
		audience: 'goobits:room-transport',
		issuer: 'goobits:access-broker',
		type: 'goobits-room+jwt'
	}
)

const verification = await verifyJwt(token, {
	secret,
	audience: 'goobits:room-transport',
	issuer: 'goobits:access-broker',
	type: 'goobits-room+jwt'
})
```

Verification pins `HS256` unless the caller supplies another explicit
HS-family allowlist. Secrets must contain at least 32 bytes. Failed
verification returns `invalid` or `expired` without exposing JOSE errors.

For externally issued JWTs, fetch and cache the provider's trusted JWKS in the
owning protocol package, then pass the static value into the same primitive:

```ts
const verification = await verifyJwtWithJwks(idToken, {
	jwks: cachedProviderJwks,
	algorithms: ['RS256'],
	issuer: 'https://issuer.example',
	audience: clientId,
	requiredClaims: ['iss', 'aud', 'sub', 'iat', 'exp']
})
```

Security performs no network I/O. It snapshots and bounds the key set, accepts
only asymmetric public signing keys, and requires callers to pin algorithms,
issuer, audience, and claims. Provider discovery, cache policy, nonce handling,
and account semantics belong to the consuming authentication protocol.

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
	createIncrementalHasher,
	createSecurityProof,
	randomHex,
	sealJson,
	verifySecurityProof
} from '@goobits/security/crypto'

const key = randomHex(32)
const sealed = await sealJson({ refreshToken: 'secret' }, { key })

const hasher = await createIncrementalHasher('blake3')
hasher.update(new TextEncoder().encode('first chunk'))
hasher.update(new TextEncoder().encode('second chunk'))
const contentDigest = hasher.digestHex()

const proof = await createSecurityProof(
	{ id: 'message-1' },
	{
		secret: process.env.PROOF_SECRET!,
		verificationMethod: 'hmac:app',
		domain: 'example.com',
		challenge: 'nonce-123'
	}
)

const result = await verifySecurityProof({ id: 'message-1' }, proof, {
	secret: process.env.PROOF_SECRET!,
	domain: 'example.com',
	challenge: 'nonce-123'
})
```

The `crypto` subpath is framework-agnostic. It provides encoding helpers,
random bytes and hex, one-shot SHA-256, incremental SHA-256 and BLAKE3, HMAC
signatures, AES-GCM sealing and opening, rotation-ready opaque keyrings,
authenticated framed streams, and deterministic `SecurityProof` envelopes.
`createIncrementalHasher()` accepts
`'sha-256'` or `'blake3'`, retains only the hash state as callers supply chunks,
and finalizes when `digestHex()` is called. Updating or finalizing it again
throws. Product permissions, roles, key-distribution policy, and app-specific
authorization remain outside this package.

`createFramedAeadEncryptStream()` and `createFramedAeadDecryptStream()` process
bounded AES-GCM frames and authenticate their version, order, terminal frame,
and caller-supplied context. They are intended for large private artifacts
that must remain encrypted at rest without buffering the full payload.

For environment-backed rotation, `createAesGcmKeyringFromJson` accepts a strict
JSON object with `activeKeyId` and a `keys` map of hex-encoded AES keys. The
returned keyring exposes only the active key ID; applications retain ownership
of the environment variable name and rotation policy.

Narrow imports are also available: `@goobits/security/crypto/encoding`,
`@goobits/security/crypto/signatures`, `@goobits/security/crypto/aead`,
`@goobits/security/crypto/framed-aead`, and
`@goobits/security/crypto/proof`.

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

**Multi-instance deployment?** Swap the in-memory store for a Redis one. The
package accepts a structural `RedisLike` client; this example uses host-owned
`ioredis`, but `ioredis` is not a package dependency or peer dependency:

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

The default `MemoryCsrfStore` retains at most 10,000 tracked tokens. Configure a
different deterministic bound with `new MemoryCsrfStore({ maxKeys })`. When the
store reaches that bound it removes expired tokens first, then evicts the oldest
active token rather than allowing attacker-controlled identifiers to grow memory
without limit.

⚠️ **`cookieOptions` replaces defaults, doesn't merge.** If you supply your own `cookieOptions`, you also lose the sensible defaults (`HttpOnly`, `SameSite=Lax`, etc.). Copy the defaults first if you only want to tweak one field.

### `failClosed`: expiry checks fail closed by default

Store errors (Redis down, etc.) make expiry-checked validation fail by default.
Only an explicit availability-over-correctness policy should opt out:

```ts
const csrf = createCsrf({ failClosed: false })

// On a route that explicitly checks expiration:
if (!(await csrf.validate(event.request, { checkExpiry: true }))) {
	return new Response('CSRF validation failed', { status: 403 })
}
```

ℹ️ **Scope**: `failClosed` is consulted inside the expiry-check path (`isTokenExpired`). It takes effect when you pass `{ checkExpiry: true }` to `validate()`. Without `checkExpiry`, the store isn't queried at all so `failClosed` has nothing to gate.

### SvelteKit adapter

```ts
import { createSvelteKitCsrf } from '@goobits/security/csrf/sveltekit'

export const csrf = createSvelteKitCsrf({
	cookieName: 'csrf_token',
	tokenFieldName: 'csrf_token',
	cookieOptions: {
		httpOnly: true,
		secure: process.env.NODE_ENV === 'production',
		sameSite: 'strict',
		path: '/',
		maxAge: 60 * 60 * 24
	}
})

// src/hooks.server.ts
export const handle = csrf.handle

// A token endpoint or page server load:
const token = await csrf.getOrCreate(event)
```

The adapter checks headers, URL-encoded forms, multipart forms, and JSON bodies.
Body inspection is bounded to 64 KiB by default. It uses stateless double-submit
cookies by default, so cookie expiry owns the token lifecycle without requiring
replica-local memory. Set `trackExpiry: true` only with a shared token store.

### `disabled`: tests only

Set via `DISABLE_CSRF=true` env var or `createCsrf({ disabled: true })`. `createCsrf()` **throws synchronously** if either is set when `NODE_ENV === 'production'`, failing loud and never silently disabled in prod.

### `serializeCookie` rejects illegal characters

The package validates cookie name + value at write time against RFC 6265's allowed character class. Any cookie value containing CRLF, `;`, `,`, `"`, `\`, or whitespace throws synchronously. This is automatic, requiring no action on your part, but it does mean a future custom `cookieOptions` change is constrained to the RFC-legal set.

## CSP

```ts
import { buildCsp } from '@goobits/security/csp'

const isProd = process.env.NODE_ENV === 'production'
// In SvelteKit/Vite, use `import.meta.env.PROD` instead.

response.headers.set(
	'Content-Security-Policy',
	buildCsp({
		mode: isProd ? 'production' : 'development',
		nonce: locals.cspNonce,
		extraSources: {
			'script-src': ['https://js.stripe.com'],
			'connect-src': ['https://api.stripe.com'],
			'img-src': ['https://cdn.example.com', 'data:']
		}
	})
)
```

The package has no hardcoded vendor list. You supply your own `extraSources`.

## Rate limiting

```ts
import { createRateLimiter } from '@goobits/security/rate-limit'
import { createRateLimitHandle } from '@goobits/security/rate-limit/sveltekit'

const limiter = createRateLimiter({
	windows: [
		{ name: 'burst', windowMs: 60_000, maxEvents: 5 },
		{ name: 'hour', windowMs: 3_600_000, maxEvents: 60 }
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

Window names must be non-empty, and `windowMs`/`maxEvents` must be positive
safe integers. Invalid or non-finite policy values fail at construction time.

⚠️ **Multi-instance deployment?** The default `MemoryRateLimitStore` keeps counters per-process. Each replica enforces an independent budget, so a 5-pod deployment effectively allows `5 × maxEvents`. Use `PostgresRateLimitStore` or another shared `RateLimitStore` implementation for multi-process production environments.

When a durable store needs an explicit outage policy, wrap it once at the store
boundary. Closed mode propagates the original failure; fallback mode requires a
specific fallback store instead of silently constructing one:

```ts
import {
	MemoryRateLimitStore,
	PostgresRateLimitStore,
	createResilientRateLimitStore,
	postgresRateLimitSchemaSql
} from '@goobits/security/rate-limit'

await pool.query(postgresRateLimitSchemaSql())
const durableStore = new PostgresRateLimitStore(pool)

const store = createResilientRateLimitStore({
	primary: durableStore,
	failureMode: 'fallback',
	fallback: new MemoryRateLimitStore()
})
```

Authentication and other abuse-sensitive production routes should normally use
`failureMode: 'closed'`. Applications still own that availability decision.

⚠️ **`getClientIP` trusts NO proxy headers by default.** This is intentional: blindly trusting `x-forwarded-for` lets attackers spoof the identifier. To enable header trust:

```ts
import { getClientIP } from '@goobits/security/rate-limit'

// Cloudflare:
const ip = getClientIP(event.request, { trustHeaders: ['cf-connecting-ip'] })

// AWS ALB / GCP LB (configured to strip client-supplied XFF):
const ip = getClientIP(event.request, { trustHeaders: ['x-forwarded-for'] })

// Append-style XFF behind two trusted proxy hops:
const ip = getClientIP(event.request, {
	trustHeaders: ['x-forwarded-for'],
	forwardedForTrustedProxyHops: 2
})
```

In SvelteKit, prefer `event.getClientAddress()`, which honors your platform adapter's trusted-proxy config.

Authentication-specific limiter presets live with the policy they encode in
`@goobits/auth/security`. This package intentionally exposes only the generic
rate-limiting mechanism:

```ts
import { createRateLimiter } from '@goobits/security/rate-limit'

const limiter = createRateLimiter({
	windows: [{ name: 'write', windowMs: 60_000, maxEvents: 10 }]
})
```

Use a shared `RateLimitStore` (for example Redis or D1) when counters must be
consistent across application instances.

Custom in-memory store config (e.g. tuning cleanup and identifier bounds):

```ts
import { MemoryRateLimitStore, createRateLimiter } from '@goobits/security/rate-limit'

const store = new MemoryRateLimitStore({
	cleanupProbability: 0.05, // 5% per increment
	maxKeys: 25_000
})
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
		body: z.object({ email: z.email(), name: z.string().min(1) }), // Zod v4 syntax
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
	jwtSecret: process.env.JWT_SECRET!, // >= 32 chars  -  throws otherwise
	apiKey: process.env.ADMIN_API_KEY, // optional fallback
	algorithms: ['HS256'], // default: ['HS256'] (pinned tight)
	audience: 'my-app', // optional  -  rejected if token aud differs
	issuer: 'my-auth-service', // optional  -  rejected if token iss differs
	clockTolerance: 30 // optional  -  seconds of skew tolerated on exp/nbf
})

export async function POST({ request }) {
	const result = await adminAuth.requireAdmin(request)
	if (!result.authenticated) {
		return new Response('Unauthorized', { status: 401 })
	}
	// result.user.id, result.method ('jwt' | 'api-key')
}

// Issue a new token (NOTE: async since the v2.0.0 jose swap):
const token = await adminAuth.createAdminToken({ id: 'user-1', role: 'admin' })

// Numeric tokenTtl is RELATIVE seconds (1 hour below), NOT absolute UNIX time:
const shortToken = await adminAuth.createAdminToken({ id: 'u1', role: 'admin' }, 3600)

// Generate a fresh API key (256-bit, hex-encoded)  -  store this once at
// provisioning time in your secret manager; do not regenerate per request:
const key = generateAdminApiKey()
```

⚠️ **`jwtSecret` must be ≥32 bytes.** `createAdminAuth()` throws at construction time on shorter secrets. Use a cryptographically random secret.

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
	failureMode: 'throw',
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
		// Additional keys extend Security's mandatory defaults. Matching is
		// case-insensitive and recurses into nested objects and arrays.
		redactKeys: ['password', 'token', 'creditCard', 'ssn']
	},
	async (event) => {
		/* ... */ return new Response('OK')
	}
)

// Or call directly:
await auditor.log({
	action: 'user.login',
	outcome: 'success',
	actorId: user.id
})
```

Cloudflare D1 consumers can use the canonical sink and add product-specific PII
field names to the default secret redaction set:

```ts
import { createD1AuditSink } from '@goobits/security/audit/d1'

const sink = createD1AuditSink({
	db: env.DB,
	tableName: 'security_audit_events',
	redactKeys: ['email']
})
```

Custom redaction keys extend Security's default secret set. The D1 sink validates
its table identifier, caps structured detail and scalar fields, serializes
bigints safely, omits arbitrary error messages, and reports storage
failures without logging database error messages or event values.

## Request origin

Use `verifyRequestOrigin()` as the shared browser-mutation boundary. Applications
provide their exact trusted origins; Security owns bounded Fetch Metadata,
`Origin`, and `Referer` parsing.

```ts
import { verifyRequestOrigin } from '@goobits/security/request-origin'

const result = verifyRequestOrigin({
	request: event.request,
	requestUrl: event.url,
	allowedOrigins: [env.PUBLIC_SITE_URL]
})
if (!result.ok) return new Response('Invalid origin', { status: 403 })
```

## Alerting

```ts
import { createSecurityAlerter, createWebhookChannel } from '@goobits/security/alerting'

const slack = createWebhookChannel({
	url: process.env.SLACK_WEBHOOK_URL!,
	timeoutMs: 5000,
	transform: (a) => ({
		text: `*[${a.severity.toUpperCase()}]* ${a.title}\n${a.message}`
	})
})

const alerter = createSecurityAlerter({
	channels: [slack],
	rules: [
		// Alert on any admin-route denial:
		(event) =>
			event.action.startsWith('admin.') && event.outcome === 'denied'
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

Webhook delivery aborts after five seconds by default so an unavailable alert
receiver cannot hold the calling security pipeline open. Set `timeoutMs` to a
positive finite duration when a different bound is required.

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
- Unknown or absent `NODE_ENV` values use production-safe defaults. Development
  bypasses activate only for explicit `development` or `test` modes.

Apps that need the same decision for secure cookies or other security defaults
should use the public runtime helper instead of interpreting `NODE_ENV`
themselves:

```ts
import { isProductionRuntime } from '@goobits/security/runtime'

const secure = isProductionRuntime(platform?.env?.NODE_ENV)
```

Pass an explicit deployment binding on runtimes that do not expose
`process.env`. Calling the helper with no argument reads `process.env.NODE_ENV`;
passing an explicitly absent binding (`undefined`) is deliberately fail-closed
and returns `true`.

### Per-module runtime compatibility

| Module                   | Node ≥22         | Bun              | Deno             | Cloudflare Workers                 |
| ------------------------ | ---------------- | ---------------- | ---------------- | ---------------------------------- |
| `csrf`                   | ✅               | ✅               | ✅               | ✅                                 |
| `csrf/sveltekit` †       | ✅               | ✅               | ✅               | ✅                                 |
| `csrf-redis` ‡           | client-dependent | client-dependent | client-dependent | client-dependent                   |
| `csp`                    | ✅               | ✅               | ✅               | ✅                                 |
| `recaptcha`              | ✅               | ✅               | ✅               | ✅                                 |
| `crypto`                 | ✅               | ✅               | ✅               | ✅                                 |
| `identity`               | ✅               | ✅               | ✅               | ✅                                 |
| `validation` †           | ✅               | ✅               | ✅               | ✅                                 |
| `rate-limit`             | ✅               | ✅               | ✅               | ✅                                 |
| `rate-limit/sveltekit` † | ✅               | ✅               | ✅               | ✅                                 |
| `principal-auth`         | ✅               | ✅               | ✅               | ✅ (uses `jose`, Web Crypto-based) |
| `admin-auth`             | ✅               | ✅               | ✅               | ✅ (uses `jose`, Web Crypto-based) |
| `audit`                  | ✅               | ✅               | ✅               | ✅                                 |
| `audit/sveltekit` †      | ✅               | ✅               | ✅               | ✅                                 |
| `alerting`               | ✅               | ✅               | ✅               | ✅                                 |
| `logger`                 | ✅               | ✅               | ✅               | ✅                                 |

† SvelteKit adapter: types reference `@sveltejs/kit`. Use the parent subpath (`validation`'s `getInputValidator`, `rate-limit`'s `createRateLimiter`, `audit`'s `createAuditLogger`) directly for framework-agnostic usage.

‡ `csrf-redis` imports no Redis library. Runtime support depends on the host-supplied client satisfying the exported `RedisLike` contract.

Modules use the Web Crypto API on `globalThis.crypto` for randomness and
signing. Incremental SHA-256 and BLAKE3 use cross-runtime `hash-wasm`. No module
imports from `node:crypto`, `node:buffer`, or another Node-only built-in.

> Continuous integration exercises Node 22. Bun, Deno, and Cloudflare Workers are validated manually; if you hit a runtime-specific issue, please open an issue with the runtime version and a minimal repro.

### Required env vars (when used)

| Module       | Variable                              | Required?                                              |
| ------------ | ------------------------------------- | ------------------------------------------------------ |
| `recaptcha`  | `RECAPTCHA_SECRET_KEY`                | Yes (or pass `secretKey` via options)                  |
| `admin-auth` | (none; `jwtSecret` passed via config) | n/a                                                    |
| `csrf`       | `DISABLE_CSRF=true`                   | Tests only; **throws at startup if set in production** |
| `csrf`       | `NODE_ENV=production`                 | Read for cookie `Secure` flag default                  |
| `recaptcha`  | `NODE_ENV`                            | Read to gate `allowInDevelopment` (default off)        |

The package never reads env vars except via these explicit fallbacks. **Best practice**: pass secrets explicitly via config and don't rely on env-var fallbacks in production code.

---

## License

MIT. See [LICENSE](./LICENSE).
