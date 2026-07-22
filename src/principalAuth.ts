/**
 * Generic principal authentication  -  JWT bearer token + API key fallback.
 *
 * This module authenticates who is calling. Product permissions, roles,
 * relationship grants, and resource authorization stay in consumer code.
 *
 * @module @goobits/security/principal-auth
 */

import { errors, jwtVerify, type JWTPayload, SignJWT } from 'jose'

import { timingSafeEqualBytes, toBytes } from './_internal/crypto.js'
import { resolveLogger } from './_internal/resolveLogger.js'
import { parseBearerToken } from './httpCredentials.js'
import type { Logger } from './logger.js'

/** Principal Auth Algorithm shape used for signed principals, API keys, and request authentication. */
export type PrincipalAuthAlgorithm = 'HS256' | 'HS384' | 'HS512'

/** Auth Principal shape used for signed principals, API keys, and request authentication. */
export interface AuthPrincipal {
	id: string
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
export type PrincipalAuthMethod = 'jwt' | 'apikey'

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

function normalizeRoles(value: unknown): string[] | undefined {
	if (value === undefined) return undefined
	if (!Array.isArray(value)) return undefined
	const roles = value.filter(
		(entry): entry is string => typeof entry === 'string' && entry.length > 0
	)
	return roles.length === value.length ? roles : undefined
}

function principalFromPayload(payload: JWTPayload): AuthPrincipal | null {
	const id = (payload as { id?: unknown }).id ?? payload.sub
	if (typeof id !== 'string' || !id) return null
	const roles = normalizeRoles(payload['roles'])
	return {
		...payload,
		id,
		...(roles ? { roles } : {})
	}
}

function normalizeApiKeys(config: PrincipalAuthConfig): PrincipalApiKey[] {
	const keys = [...(config.apiKeys ?? [])]
	if (config.apiKey) {
		keys.push({
			key: config.apiKey,
			principal: { id: 'api-key-principal', roles: ['service'] }
		})
	}
	return keys
}

function verifyApiKey(presentedKey: string, keys: PrincipalApiKey[]): AuthPrincipal | null {
	for (const entry of keys) {
		if (timingSafeEqualBytes(toBytes(presentedKey), toBytes(entry.key))) {
			return entry.principal
		}
	}
	return null
}

function resolveExpirationTime(ttl: string | number): string | number {
	return typeof ttl === 'number' ? Math.floor(Date.now() / 1000) + ttl : ttl
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
	if (jwtSecret.length < 32) {
		throw new Error(
			'@goobits/security/principal-auth: jwtSecret must be at least 32 characters. Use a cryptographically random secret.'
		)
	}
	if (algorithms.length === 0) {
		throw new Error(
			'@goobits/security/principal-auth: algorithms must include at least one algorithm'
		)
	}

	const secretBytes = toBytes(jwtSecret)
	const apiKeys = normalizeApiKeys(config)
	const verifyOptions: Parameters<typeof jwtVerify>[2] = { algorithms }
	if (audience !== undefined) verifyOptions.audience = audience
	if (issuer !== undefined) verifyOptions.issuer = issuer
	if (clockTolerance !== undefined) verifyOptions.clockTolerance = clockTolerance

	async function authorize(
		principal: AuthPrincipal,
		method: PrincipalAuthMethod,
		request: Request
	): Promise<boolean> {
		return (await config.authorizePrincipal?.(principal, { method, request })) ?? true
	}

	async function verifyJwt(token: string): Promise<AuthPrincipal | null> {
		try {
			const { payload } = await jwtVerify(token, secretBytes, verifyOptions)
			const principal = principalFromPayload(payload)
			if (!principal) {
				log.warn('Principal JWT lacks `id` or `sub` claim')
				return null
			}
			return principal
		} catch (err) {
			if (err instanceof errors.JWTExpired) {
				log.warn('Principal JWT expired')
			} else if (err instanceof errors.JOSEError) {
				log.warn('Principal JWT verification failed', { code: err.code })
			} else {
				log.warn('Principal JWT verification threw', { error: String(err) })
			}
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
			const principal = verifyApiKey(presentedApiKey, apiKeys)
			if (!principal) return { authenticated: false, reason: 'invalid-apikey' }
			if (!(await authorize(principal, 'apikey', request))) {
				return { authenticated: false, reason: 'forbidden' }
			}
			return { authenticated: true, principal, method: 'apikey' }
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
		const ttl = overrideTtl ?? tokenTtl
		const builder = new SignJWT(principal)
			.setProtectedHeader({ alg: algorithms[0] ?? 'HS256' })
			.setIssuedAt()
			.setExpirationTime(resolveExpirationTime(ttl))

		if (audience !== undefined) {
			builder.setAudience(audience)
		}
		if (issuer !== undefined) {
			builder.setIssuer(typeof issuer === 'string' ? issuer : (issuer[0] ?? ''))
		}

		return builder.sign(secretBytes)
	}

	return {
		authenticate,
		requirePrincipal,
		createPrincipalToken
	}
}
