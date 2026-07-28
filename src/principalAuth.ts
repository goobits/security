/**
 * Generic principal authentication  -  JWT bearer token + API key fallback.
 *
 * This module authenticates who is calling. Product permissions, roles,
 * relationship grants, and resource authorization stay in consumer code.
 *
 * @module @goobits/security/principal-auth
 */

import type { JWTPayload } from 'jose'

import { constantTimeEqual, textToBytes } from './crypto/index.js'
import { resolveLogger } from './_internal/resolveLogger.js'
import { parseBearerToken } from './httpCredentials.js'
import type { PrincipalIdentity } from './identity/principal.js'
import { signJwt, verifyJwt as verifyJwtToken } from './jwt.js'
import type { Logger } from './logger.js'
import { safeErrorContext } from './logger.js'

/** Principal Auth Algorithm shape used for signed principals, API keys, and request authentication. */
export type PrincipalAuthAlgorithm = 'HS256' | 'HS384' | 'HS512'

/** Auth Principal shape used for signed principals, API keys, and request authentication. */
export interface AuthPrincipal extends PrincipalIdentity {
	roles?: string[]
	[key: string]: unknown
}

/** Principal Api Key shape used for signed principals, API keys, and request authentication. */
export interface PrincipalApiKey {
	key: string
	principal: AuthPrincipal
}

/** Principal Auth Config shape used for signed principals, API keys, and request authentication. */
export interface PrincipalAuthConfig {
	/** JWT signing secret. Required. Must be at least 32 bytes for HS-family algorithms. */
	jwtSecret: string
	/** One or more API keys mapped to explicit principals. */
	apiKeys?: PrincipalApiKey[]
	/** Convenience single API key. Maps to `{ id: 'api-key-principal', roles: ['service'] }`. */
	apiKey?: string
	/** Header to read API keys from. Default: `x-api-key`. */
	apiKeyHeader?: string
	/** Default JWT TTL for `createPrincipalToken()`. Number values are relative seconds. */
	tokenTtl?: string | number
	/** Allowed signing algorithms. Default: `['HS256']`. */
	algorithms?: PrincipalAuthAlgorithm[]
	/** Expected JWT audience. */
	audience?: string | string[]
	/** Expected JWT issuer. */
	issuer?: string | string[]
	/** Clock-skew tolerance in seconds for JWT time checks. Default: 0. */
	clockTolerance?: number
	/** Optional final gate after credentials verify. Return false to reject. */
	authorizePrincipal?: (
		principal: AuthPrincipal,
		context: { method: PrincipalAuthMethod; request: Request }
	) => boolean | Promise<boolean>
	/** Pluggable logger. Default: silent. */
	logger?: Logger
}

/** Principal Auth Method shape used for signed principals, API keys, and request authentication. */
export type PrincipalAuthMethod = 'jwt' | 'api-key'

/** Principal Auth Failure Reason shape used for signed principals, API keys, and request authentication. */
export type PrincipalAuthFailureReason = 'missing' | 'invalid-jwt' | 'invalid-apikey' | 'forbidden'

/** Principal Auth Result shape used for signed principals, API keys, and request authentication. */
export type PrincipalAuthResult =
	| { authenticated: true; principal: AuthPrincipal; method: PrincipalAuthMethod }
	| { authenticated: false; reason: PrincipalAuthFailureReason }

/** Principal Auth shape used for signed principals, API keys, and request authentication. */
export interface PrincipalAuth {
	authenticate(request: Request): Promise<PrincipalAuthResult>
	requirePrincipal(request: Request): Promise<PrincipalAuthResult>
	createPrincipalToken(principal: AuthPrincipal, overrideTtl?: string | number): Promise<string>
}

const MIN_API_KEY_BYTES = 32
const MAX_API_KEY_BYTES = 4_096
const MAX_PRINCIPAL_ID_LENGTH = 256
const MAX_PRINCIPAL_ROLES = 64
const MAX_ROLE_LENGTH = 128

function normalizeRoles(value: unknown): string[] | undefined | null {
	if (value === undefined) return undefined
	if (!Array.isArray(value) || value.length > MAX_PRINCIPAL_ROLES) return null
	const roles: string[] = []
	for (const entry of value) {
		if (
			typeof entry !== 'string' ||
			entry.length === 0 ||
			entry.length > MAX_ROLE_LENGTH ||
			entry.trim() !== entry ||
			/[\u0000-\u001f\u007f]/.test(entry) ||
			roles.includes(entry)
		) {
			return null
		}
		roles.push(entry)
	}
	return roles
}

function normalizePrincipal(value: unknown): AuthPrincipal | null {
	if (!value || typeof value !== 'object' || Array.isArray(value)) return null
	const principal = value as AuthPrincipal
	if (
		typeof principal.id !== 'string' ||
		principal.id.length === 0 ||
		principal.id.length > MAX_PRINCIPAL_ID_LENGTH ||
		principal.id.trim() !== principal.id ||
		/[\u0000-\u001f\u007f]/.test(principal.id)
	) {
		return null
	}
	const roles = normalizeRoles(principal.roles)
	if (roles === null) return null
	return {
		...principal,
		id: principal.id,
		...(roles === undefined ? {} : { roles })
	}
}

function principalFromPayload(payload: JWTPayload): AuthPrincipal | null {
	const id = (payload as { id?: unknown }).id ?? payload.sub
	if (typeof id !== 'string' || !id) return null
	const roles = normalizeRoles(payload['roles'])
	if (roles === null) return null
	return normalizePrincipal({
		...payload,
		id,
		...(roles ? { roles } : {})
	})
}

function normalizeApiKeys(config: PrincipalAuthConfig): PrincipalApiKey[] {
	const keys = [...(config.apiKeys ?? [])]
	if (config.apiKey !== undefined) {
		keys.push({
			key: config.apiKey,
			principal: { id: 'api-key-principal', roles: ['service'] }
		})
	}
	const seen = new Set<string>()
	return keys.map((entry) => {
		if (!entry || typeof entry.key !== 'string') {
			throw new Error('@goobits/security/principal-auth: API key must be a string')
		}
		const keyBytes = textToBytes(entry.key).byteLength
		if (keyBytes < MIN_API_KEY_BYTES || keyBytes > MAX_API_KEY_BYTES) {
			throw new Error(
				`@goobits/security/principal-auth: API keys must contain ${MIN_API_KEY_BYTES}-${MAX_API_KEY_BYTES} bytes`
			)
		}
		if (seen.has(entry.key)) {
			throw new Error('@goobits/security/principal-auth: API keys must be unique')
		}
		seen.add(entry.key)
		const principal =
			entry.principal && typeof entry.principal === 'object'
				? normalizePrincipal(entry.principal)
				: null
		if (!principal) {
			throw new Error('@goobits/security/principal-auth: API-key principal is invalid')
		}
		return { key: entry.key, principal }
	})
}

function resolveApiKeyPrincipal(
	presentedKey: string,
	keys: PrincipalApiKey[]
): AuthPrincipal | null {
	const byteLength = textToBytes(presentedKey).byteLength
	if (byteLength < MIN_API_KEY_BYTES || byteLength > MAX_API_KEY_BYTES) return null
	for (const entry of keys) {
		if (constantTimeEqual(presentedKey, entry.key)) {
			return entry.principal
		}
	}
	return null
}

function assertExpectedClaim(
	name: 'audience' | 'issuer',
	value: string | string[] | undefined
): void {
	if (value === undefined) return
	const values = Array.isArray(value) ? value : [value]
	if (
		values.length === 0 ||
		values.some(
			(entry) =>
				typeof entry !== 'string' ||
				entry.length === 0 ||
				entry.length > 512 ||
				entry.trim() !== entry ||
				/[\u0000-\u001f\u007f]/.test(entry)
		)
	) {
		throw new Error(`@goobits/security/principal-auth: ${name} is invalid`)
	}
}

/** Create Principal Auth shape used for signed principals, API keys, and request authentication. */
export function createPrincipalAuth(config: PrincipalAuthConfig): PrincipalAuth {
	const {
		jwtSecret,
		tokenTtl = '24h',
		algorithms = ['HS256'],
		audience,
		issuer,
		clockTolerance,
		apiKeyHeader = 'x-api-key'
	} = config
	const log = resolveLogger(config.logger)

	if (!jwtSecret) {
		throw new Error('@goobits/security/principal-auth: jwtSecret is required')
	}
	if (textToBytes(jwtSecret).byteLength < 32) {
		throw new Error(
			'@goobits/security/principal-auth: jwtSecret must be at least 32 bytes. Use a cryptographically random secret.'
		)
	}
	if (
		algorithms.length === 0 ||
		new Set(algorithms).size !== algorithms.length ||
		algorithms.some((algorithm) => !['HS256', 'HS384', 'HS512'].includes(algorithm))
	) {
		throw new Error(
			'@goobits/security/principal-auth: algorithms must be a non-empty unique HS-family list'
		)
	}
	if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$/.test(apiKeyHeader)) {
		throw new Error('@goobits/security/principal-auth: apiKeyHeader is invalid')
	}
	if (typeof tokenTtl === 'string' && !tokenTtl.trim()) {
		throw new Error('@goobits/security/principal-auth: tokenTtl is invalid')
	}
	if (
		clockTolerance !== undefined &&
		(typeof clockTolerance !== 'number' ||
			!Number.isFinite(clockTolerance) ||
			clockTolerance < 0)
	) {
		throw new Error('@goobits/security/principal-auth: clockTolerance must be non-negative')
	}
	assertExpectedClaim('audience', audience)
	assertExpectedClaim('issuer', issuer)

	const apiKeys = normalizeApiKeys(config)

	async function authorize(
		principal: AuthPrincipal,
		method: PrincipalAuthMethod,
		request: Request
	): Promise<boolean> {
		return (await config.authorizePrincipal?.(principal, { method, request })) ?? true
	}

	async function verifyJwt(token: string): Promise<AuthPrincipal | null> {
		try {
			const verification = await verifyJwtToken(token, {
				secret: jwtSecret,
				algorithms,
				...(audience === undefined ? {} : { audience }),
				...(issuer === undefined ? {} : { issuer }),
				...(clockTolerance === undefined ? {} : { clockTolerance })
			})
			if (!verification.ok) {
				log.warn(
					verification.reason === 'expired'
						? 'Principal JWT expired'
						: 'Principal JWT verification failed'
				)
				return null
			}
			const principal = principalFromPayload(verification.payload)
			if (!principal) {
				log.warn('Principal JWT lacks `id` or `sub` claim')
				return null
			}
			return principal
		} catch (err) {
			log.warn('Principal JWT verification threw', safeErrorContext(err))
			return null
		}
	}

	async function authenticate(request: Request): Promise<PrincipalAuthResult> {
		const bearer = parseBearerToken(request.headers.get('authorization'))
		if (bearer) {
			const principal = await verifyJwt(bearer)
			if (!principal) return { authenticated: false, reason: 'invalid-jwt' }
			if (!(await authorize(principal, 'jwt', request))) {
				return { authenticated: false, reason: 'forbidden' }
			}
			return { authenticated: true, principal, method: 'jwt' }
		}

		const presentedApiKey = request.headers.get(apiKeyHeader)
		if (presentedApiKey) {
			const principal = resolveApiKeyPrincipal(presentedApiKey, apiKeys)
			if (!principal) return { authenticated: false, reason: 'invalid-apikey' }
			if (!(await authorize(principal, 'api-key', request))) {
				return { authenticated: false, reason: 'forbidden' }
			}
			return { authenticated: true, principal, method: 'api-key' }
		}

		return { authenticated: false, reason: 'missing' }
	}

	async function requirePrincipal(request: Request): Promise<PrincipalAuthResult> {
		const result = await authenticate(request)
		if (!result.authenticated) {
			log.warn('Principal access denied', { reason: result.reason })
		}
		return result
	}

	async function createPrincipalToken(
		principal: AuthPrincipal,
		overrideTtl?: string | number
	): Promise<string> {
		const normalizedPrincipal = normalizePrincipal(principal)
		if (!normalizedPrincipal) {
			throw new Error('@goobits/security/principal-auth: principal is invalid')
		}
		const ttl = overrideTtl ?? tokenTtl
		if (typeof ttl === 'number' && (!Number.isSafeInteger(ttl) || ttl <= 0)) {
			throw new Error('@goobits/security/principal-auth: numeric token TTL must be positive')
		}
		return await signJwt(normalizedPrincipal, {
			secret: jwtSecret,
			expiresIn: ttl,
			algorithm: algorithms[0] ?? 'HS256',
			...(audience === undefined ? {} : { audience }),
			...(issuer === undefined
				? {}
				: { issuer: typeof issuer === 'string' ? issuer : (issuer[0] ?? '') })
		})
	}

	return {
		authenticate,
		requirePrincipal,
		createPrincipalToken
	}
}
