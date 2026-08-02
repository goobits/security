/**
 * Admin route authentication  -  JWT bearer token + API key fallback.
 *
 * Uses [`jose`](https://github.com/panva/jose) (Web Crypto-based) so the
 * module loads cleanly on Cloudflare Workers, Deno, Bun, and Node ≥22.
 *
 * @module @goobits/security/admin-auth
 */

import { getRandomBytes, toHex } from './_internal/crypto.js'
import { resolveLogger } from './_internal/resolveLogger.js'
import type { HmacAlgorithm } from './crypto/signatures.js'
import type { Logger } from './logger.js'
import {
	createPrincipalAuth,
	type AuthPrincipal,
	type PrincipalAuthResult
} from './principalAuth.js'

/** Admin User request or option shape for security middleware. */
export interface AdminUser extends AuthPrincipal {
	role?: string
}

/** Admin Auth Config request or option shape for security middleware. */
export interface AdminAuthConfig {
	/** JWT signing secret. Required. Must be at least 32 bytes for HS256. */
	jwtSecret: string
	/** API key fallback (optional). Requests with matching `x-admin-api-key` are also accepted. */
	apiKey?: string
	/**
	 * Default JWT TTL when creating tokens. Accepts:
	 *  - **number**  -  RELATIVE seconds from issuance (e.g. `86400` = 24 hours)
	 *  - **string**  -  `jose`-compatible duration like `'24h'`, `'7d'`, `'15m'`
	 *
	 * Default: `'24h'`.
	 *
	 * Note: unlike `jsonwebtoken`, the underlying `jose` library interprets a
	 * bare number passed to `setExpirationTime` as an **absolute** UNIX
	 * timestamp. We translate numeric input to `now + seconds` for you so the
	 * "relative seconds" intuition holds.
	 */
	tokenTtl?: string | number
	/** Allowed signing algorithms. Default: `['HS256']`. Pin tight. */
	algorithms?: HmacAlgorithm[]
	/**
	 * Expected `aud` claim. If set, `requireAdmin()` rejects tokens whose
	 * `aud` doesn't match. Pass through to `jose.jwtVerify`.
	 */
	audience?: string | string[]
	/**
	 * Expected `iss` claim. If set, `requireAdmin()` rejects tokens whose
	 * `iss` doesn't match.
	 */
	issuer?: string | string[]
	/**
	 * Clock-skew tolerance in seconds for `exp` / `nbf` checks. Default: 0.
	 * Set to ~30-60 for tolerant deployments across machines with imperfect
	 * NTP sync.
	 */
	clockTolerance?: number
	/** Pluggable logger. Default: silent. */
	logger?: Logger
}

/** Admin Auth Result typed model for security middleware. */
export type AdminAuthResult =
	| { authenticated: true; user: AdminUser; method: 'jwt' | 'api-key' }
	| { authenticated: false; reason: 'missing' | 'invalid-jwt' | 'not-admin' | 'invalid-apikey' }

function isAdminClaim(principal: AuthPrincipal): boolean {
	const role = principal['role']
	const isAdmin = principal['isAdmin']
	const admin = principal['admin']
	return role === 'admin' || role === 'super-admin' || isAdmin === true || admin === true
}

function toAdminResult(result: PrincipalAuthResult): AdminAuthResult {
	if (result.authenticated) {
		return {
			authenticated: true,
			user: result.principal as AdminUser,
			method: result.method
		}
	}
	return {
		authenticated: false,
		reason: result.reason === 'forbidden' ? 'not-admin' : result.reason
	}
}

/**
 * Build an admin-auth gate. Returns an object with helpers for verifying
 * requests, creating new admin tokens, and generating API keys.
 *
 * @example
 * ```ts
 * import { createAdminAuth } from '@goobits/security/admin-auth'
 *
 * const adminAuth = createAdminAuth({
 *   jwtSecret: process.env.JWT_SECRET!,
 *   apiKey: process.env.ADMIN_API_KEY
 * })
 *
 * export async function POST({ request }) {
 *   const result = await adminAuth.requireAdmin(request)
 *   if (!result.authenticated) {
 *     return new Response('Unauthorized', { status: 401 })
 *   }
 *   // result.user.id, result.method
 * }
 * ```
 */
export function createAdminAuth(config: AdminAuthConfig): AdminAuth {
	const log = resolveLogger(config.logger)
	const principalAuth = createPrincipalAuth({
		jwtSecret: config.jwtSecret,
		tokenTtl: config.tokenTtl,
		algorithms: config.algorithms,
		audience: config.audience,
		issuer: config.issuer,
		clockTolerance: config.clockTolerance,
		logger: config.logger,
		apiKeys: config.apiKey
			? [{ key: config.apiKey, principal: { id: 'api-key-admin', role: 'admin' } }]
			: [],
		apiKeyHeader: 'x-admin-api-key',
		authorizePrincipal: (principal) => isAdminClaim(principal)
	})

	async function authenticate(request: Request): Promise<AdminAuthResult> {
		return toAdminResult(await principalAuth.authenticate(request))
	}

	async function requireAdmin(request: Request): Promise<AdminAuthResult> {
		const result = await authenticate(request)
		if (!result.authenticated) {
			log.warn('Admin route access denied', { reason: result.reason })
		}
		return result
	}

	async function createAdminToken(user: AdminUser, overrideTtl?: string | number): Promise<string> {
		return principalAuth.createPrincipalToken({ ...user, role: user.role ?? 'admin' }, overrideTtl)
	}

	return { authenticate, requireAdmin, createAdminToken }
}

/** Admin Auth request or option shape for security middleware. */
export interface AdminAuth {
	authenticate(request: Request): Promise<AdminAuthResult>
	requireAdmin(request: Request): Promise<AdminAuthResult>
	createAdminToken(user: AdminUser, overrideTtl?: string | number): Promise<string>
}

/**
 * Generate a cryptographically random API key suitable for `x-admin-api-key`.
 * The returned string is 64 hex characters (256 bits).
 */
export function generateAdminApiKey(): string {
	return toHex(getRandomBytes(32))
}
