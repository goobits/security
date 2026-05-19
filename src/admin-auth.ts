/**
 * Admin route authentication — JWT bearer token + API key fallback.
 *
 * Uses [`jose`](https://github.com/panva/jose) (Web Crypto-based) so the
 * module loads cleanly on Cloudflare Workers, Deno, Bun, and Node ≥22.
 *
 * @module @goobits/security/admin-auth
 */

import { errors, jwtVerify, type JWTPayload, SignJWT } from 'jose'

import {
	getRandomBytes,
	timingSafeEqualBytes,
	toBytes,
	toHex
} from './_internal/crypto.js'
import { type Logger, resolveLogger } from './logger.js'

/** Supported HS-family algorithms. RS/ES variants would require key material. */
export type AdminAuthAlgorithm = 'HS256' | 'HS384' | 'HS512'

export interface AdminUser {
	id: string
	role?: string
	[key: string]: unknown
}

export interface AdminAuthConfig {
	/** JWT signing secret. Required. Must be at least 32 bytes for HS256. */
	jwtSecret: string
	/** API key fallback (optional). Requests with matching `x-admin-api-key` are also accepted. */
	apiKey?: string
	/**
	 * Default JWT TTL when creating tokens. Accepts:
	 *  - **number** — RELATIVE seconds from issuance (e.g. `86400` = 24 hours)
	 *  - **string** — `jose`-compatible duration like `'24h'`, `'7d'`, `'15m'`
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
	algorithms?: AdminAuthAlgorithm[]
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

export type AdminAuthResult =
	| { authenticated: true; user: AdminUser; method: 'jwt' | 'apikey' }
	| { authenticated: false; reason: 'missing' | 'invalid-jwt' | 'not-admin' | 'invalid-apikey' }

function isAdminClaim(payload: JWTPayload): boolean {
	const role = payload['role']
	const isAdmin = payload['isAdmin']
	const admin = payload['admin']
	return role === 'admin' || role === 'super-admin' || isAdmin === true || admin === true
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
	const {
		jwtSecret,
		apiKey,
		tokenTtl = '24h',
		algorithms = [ 'HS256' ],
		audience,
		issuer,
		clockTolerance
	} = config
	const log = resolveLogger(config.logger)

	if (!jwtSecret) {
		throw new Error('@goobits/security/admin-auth: jwtSecret is required')
	}
	if (jwtSecret.length < 32) {
		throw new Error(
			'@goobits/security/admin-auth: jwtSecret must be at least 32 characters. Use a cryptographically random secret.'
		)
	}
	if (algorithms.length === 0) {
		throw new Error('@goobits/security/admin-auth: algorithms must include at least one algorithm')
	}

	const secretBytes = toBytes(jwtSecret)

	// Build the jose verify options once at construction.
	const verifyOptions: Parameters<typeof jwtVerify>[2] = { algorithms }
	if (audience !== undefined) verifyOptions.audience = audience
	if (issuer !== undefined) verifyOptions.issuer = issuer
	if (clockTolerance !== undefined) verifyOptions.clockTolerance = clockTolerance

	async function verifyJwt(token: string): Promise<AdminUser | null> {
		try {
			const { payload } = await jwtVerify(token, secretBytes, verifyOptions)
			if (!isAdminClaim(payload)) {
				log.warn('Admin JWT valid but lacks admin claim', { sub: payload.sub })
				return null
			}
			const id = (payload as { id?: string }).id ?? payload.sub
			if (!id) {
				log.warn('Admin JWT lacks `id` or `sub` claim')
				return null
			}
			return { ...payload, id } as AdminUser
		} catch(err) {
			if (err instanceof errors.JWTExpired) {
				log.warn('Admin JWT expired')
			} else if (err instanceof errors.JOSEError) {
				log.warn('Admin JWT verification failed', { code: err.code })
			} else {
				log.warn('Admin JWT verification threw', { error: String(err) })
			}
			return null
		}
	}

	function verifyApiKey(presentedKey: string): boolean {
		if (!apiKey) return false
		return timingSafeEqualBytes(toBytes(presentedKey), toBytes(apiKey))
	}

	function extractBearer(authHeader: string | null): string | null {
		if (!authHeader) return null
		// Bearer token: no whitespace inside the token. Reject `Bearer foo bar`.
		const match = /^Bearer\s+(\S+)\s*$/i.exec(authHeader.trim())
		return match?.[1] ?? null
	}

	async function authenticate(request: Request): Promise<AdminAuthResult> {
		const authHeader = request.headers.get('authorization')
		const bearer = extractBearer(authHeader)

		if (bearer) {
			const user = await verifyJwt(bearer)
			if (user) return { authenticated: true, user, method: 'jwt' }
			return { authenticated: false, reason: 'invalid-jwt' }
		}

		const presentedApiKey = request.headers.get('x-admin-api-key')
		if (presentedApiKey) {
			if (verifyApiKey(presentedApiKey)) {
				return {
					authenticated: true,
					user: { id: 'api-key-admin', role: 'admin' },
					method: 'apikey'
				}
			}
			return { authenticated: false, reason: 'invalid-apikey' }
		}

		return { authenticated: false, reason: 'missing' }
	}

	async function requireAdmin(request: Request): Promise<AdminAuthResult> {
		const result = await authenticate(request)
		if (!result.authenticated) {
			log.warn('Admin route access denied', { reason: result.reason })
		}
		return result
	}

	async function createAdminToken(user: AdminUser, overrideTtl?: string | number): Promise<string> {
		const ttl = overrideTtl ?? tokenTtl
		// jose's setExpirationTime treats numbers as ABSOLUTE UNIX seconds (foot-gun!).
		// We translate consumer-supplied numbers as RELATIVE seconds from now,
		// matching the jsonwebtoken `expiresIn` convention most users expect.
		const expirationTime: string | number =
			typeof ttl === 'number'
				? Math.floor(Date.now() / 1000) + ttl
				: ttl

		const builder = new SignJWT({ ...user, role: user.role ?? 'admin' })
			.setProtectedHeader({ alg: algorithms[0] ?? 'HS256' })
			.setIssuedAt()
			.setExpirationTime(expirationTime)

		if (audience !== undefined) {
			builder.setAudience(audience)
		}
		if (issuer !== undefined) {
			// jose accepts string only for setIssuer; fall back to the first if array.
			builder.setIssuer(typeof issuer === 'string' ? issuer : (issuer[0] ?? ''))
		}

		return builder.sign(secretBytes)
	}

	return { authenticate, requireAdmin, createAdminToken }
}

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
