import {
	createLocalJWKSet,
	errors,
	jwtVerify,
	SignJWT,
	type JSONWebKeySet,
	type JWTPayload,
	type JWTVerifyGetKey,
	type JWTVerifyOptions
} from 'jose'

import { textToBytes } from './crypto/encoding.js'
import type { HmacAlgorithm } from './crypto/signatures.js'

/** @deprecated Import `HmacAlgorithm` from `@goobits/security/crypto` instead. */
export type JwtHmacAlgorithm = HmacAlgorithm

/** Options for issuing a short-lived, purpose-bound JWT. */
export type SignJwtOptions = {
	secret: string | Uint8Array
	expiresIn: string | number
	algorithm?: HmacAlgorithm
	audience?: string | string[]
	issuer?: string
	subject?: string
	jwtId?: string
	type?: string
	issuedAt?: number
}

type JwtClaimVerificationOptions = {
	audience?: string | string[]
	issuer?: string | string[]
	type?: string
	clockTolerance?: number
	currentDate?: Date
	requiredClaims?: readonly string[]
}

/** Options for verifying a purpose-bound JWT with a pinned algorithm. */
export type VerifyJwtOptions = JwtClaimVerificationOptions & {
	secret: string | Uint8Array
	algorithms?: readonly HmacAlgorithm[]
}

/** Asymmetric signature algorithms accepted by the static-JWKS verifier. */
export type JwksSignatureAlgorithm =
	| 'RS256'
	| 'RS384'
	| 'RS512'
	| 'PS256'
	| 'PS384'
	| 'PS512'
	| 'ES256'
	| 'ES384'
	| 'ES512'
	| 'EdDSA'

/**
 * Options for verifying a JWT against a caller-fetched, static public JWKS.
 *
 * The caller owns trusted-endpoint fetching and caching. This primitive owns
 * key-set bounds plus algorithm, issuer, audience, type, and claim pinning.
 */
export type VerifyJwtWithJwksOptions = Omit<
	JwtClaimVerificationOptions,
	'audience' | 'issuer' | 'requiredClaims'
> & {
	jwks: JSONWebKeySet
	algorithms: readonly JwksSignatureAlgorithm[]
	audience: string | string[]
	issuer: string | string[]
	requiredClaims: readonly string[]
	maxTokenAge?: string | number
}

/** Result of JWT verification without leaking JOSE implementation errors. */
export type JwtVerification =
	| { ok: true; payload: JWTPayload }
	| { ok: false; reason: 'expired' | 'key-not-found' | 'invalid' }

const minimumJwtHmacSecretBytes = 32
const maximumJwksKeys = 100
const maximumJwksBytes = 256 * 1024
const supportedJwksAlgorithms = new Set<JwksSignatureAlgorithm>([
	'RS256',
	'RS384',
	'RS512',
	'PS256',
	'PS384',
	'PS512',
	'ES256',
	'ES384',
	'ES512',
	'EdDSA'
])

/** Issues an RFC 7519 JWT using the repository's pinned JOSE implementation. */
export async function signJwt(payload: JWTPayload, options: SignJwtOptions): Promise<string> {
	const secret = jwtSecretBytes(options.secret)
	const issuedAt = options.issuedAt ?? Math.floor(Date.now() / 1000)
	const expiresAt =
		typeof options.expiresIn === 'number'
			? issuedAt + positiveLifetime(options.expiresIn)
			: requiredText(options.expiresIn, 'JWT expiration')
	let token = new SignJWT(payload)
		.setProtectedHeader({
			alg: options.algorithm ?? 'HS256',
			...(options.type ? { typ: options.type } : {})
		})
		.setIssuedAt(issuedAt)
		.setExpirationTime(expiresAt)
	if (options.audience !== undefined) token = token.setAudience(options.audience)
	if (options.issuer !== undefined) token = token.setIssuer(options.issuer)
	if (options.subject !== undefined) token = token.setSubject(options.subject)
	if (options.jwtId !== undefined) token = token.setJti(options.jwtId)
	return await token.sign(secret)
}

/** Verifies an RFC 7519 JWT with algorithm, audience, issuer, and type pinning. */
export async function verifyJwt(
	token: string,
	options: VerifyJwtOptions
): Promise<JwtVerification> {
	return await verifyJwtWithKey(token, async () => jwtSecretBytes(options.secret), {
		...options,
		algorithms: [...(options.algorithms ?? ['HS256'])]
	})
}

/**
 * Verifies a JWT against a bounded snapshot of a caller-supplied public JWKS.
 *
 * This function never performs network I/O and rejects symmetric/private keys.
 * Malformed or non-matching key sets return the same opaque invalid result as
 * other signature failures.
 */
export async function verifyJwtWithJwks(
	token: string,
	options: VerifyJwtWithJwksOptions
): Promise<JwtVerification> {
	const algorithms = validateJwksAlgorithms(options.algorithms)
	validateExpectedClaim('audience', options.audience)
	validateExpectedClaim('issuer', options.issuer)
	validateRequiredClaims(options.requiredClaims)

	try {
		const keySet = createLocalJWKSet(snapshotPublicJwks(options.jwks))
		return await verifyJwtWithKey(token, keySet, {
			...options,
			algorithms
		})
	} catch (error) {
		return failedVerification(error)
	}
}

async function verifyJwtWithKey(
	token: string,
	getKey: JWTVerifyGetKey,
	options: JwtClaimVerificationOptions & {
		algorithms: readonly string[]
		maxTokenAge?: string | number
	}
): Promise<JwtVerification> {
	try {
		const verificationOptions: JWTVerifyOptions = {
			algorithms: [...options.algorithms],
			...(options.audience === undefined ? {} : { audience: options.audience }),
			...(options.issuer === undefined ? {} : { issuer: options.issuer }),
			...(options.clockTolerance === undefined ? {} : { clockTolerance: options.clockTolerance }),
			...(options.currentDate === undefined ? {} : { currentDate: options.currentDate }),
			...(options.requiredClaims === undefined
				? {}
				: { requiredClaims: [...options.requiredClaims] }),
			...(options.maxTokenAge === undefined ? {} : { maxTokenAge: options.maxTokenAge })
		}
		const { payload, protectedHeader } = await jwtVerify(
			requiredText(token, 'JWT'),
			getKey,
			verificationOptions
		)
		if (options.type !== undefined && protectedHeader.typ !== options.type) {
			return { ok: false, reason: 'invalid' }
		}
		return { ok: true, payload }
	} catch (error) {
		return failedVerification(error)
	}
}

function failedVerification(error: unknown): JwtVerification {
	return {
		ok: false,
		reason:
			error instanceof errors.JWTExpired
				? 'expired'
				: error instanceof errors.JWKSNoMatchingKey
					? 'key-not-found'
					: 'invalid'
	}
}

function validateJwksAlgorithms(
	algorithms: readonly JwksSignatureAlgorithm[]
): JwksSignatureAlgorithm[] {
	if (algorithms.length === 0) {
		throw new Error('@goobits/security/jwt: at least one JWKS algorithm is required')
	}
	const unique = new Set(algorithms)
	if (
		unique.size !== algorithms.length ||
		[...unique].some((value) => !supportedJwksAlgorithms.has(value))
	) {
		throw new Error('@goobits/security/jwt: JWKS algorithms must be unique and supported')
	}
	return [...unique]
}

function validateExpectedClaim(name: 'audience' | 'issuer', value: string | string[]): void {
	const values = typeof value === 'string' ? [value] : value
	if (values.length === 0 || values.length > 20 || values.some((entry) => !entry.trim())) {
		throw new Error(`@goobits/security/jwt: expected ${name} must contain 1-20 values`)
	}
}

function validateRequiredClaims(claims: readonly string[]): void {
	if (
		claims.length === 0 ||
		claims.length > 20 ||
		new Set(claims).size !== claims.length ||
		claims.some((claim) => !claim.trim())
	) {
		throw new Error('@goobits/security/jwt: required claims must contain 1-20 unique names')
	}
}

function snapshotPublicJwks(jwks: JSONWebKeySet): JSONWebKeySet {
	const snapshot = structuredClone(jwks)
	if (
		!Array.isArray(snapshot.keys) ||
		snapshot.keys.length === 0 ||
		snapshot.keys.length > maximumJwksKeys
	) {
		throw new Error('@goobits/security/jwt: JWKS must contain 1-100 public keys')
	}
	if (new TextEncoder().encode(JSON.stringify(snapshot)).byteLength > maximumJwksBytes) {
		throw new Error('@goobits/security/jwt: JWKS exceeds the 256 KiB limit')
	}

	const keyIds = new Set<string>()
	for (const key of snapshot.keys) {
		if (!['RSA', 'EC', 'OKP'].includes(key.kty ?? '') || hasPrivateKeyMaterial(key)) {
			throw new Error('@goobits/security/jwt: JWKS must contain only asymmetric public keys')
		}
		if (key.use !== undefined && key.use !== 'sig') {
			throw new Error('@goobits/security/jwt: JWKS keys must be signing keys')
		}
		if (key.key_ops !== undefined && !key.key_ops.includes('verify')) {
			throw new Error('@goobits/security/jwt: JWKS key operations must allow verification')
		}
		if (key.kid !== undefined) {
			if (!key.kid.trim() || keyIds.has(key.kid)) {
				throw new Error('@goobits/security/jwt: JWKS key IDs must be non-empty and unique')
			}
			keyIds.add(key.kid)
		}
	}
	return snapshot
}

function hasPrivateKeyMaterial(key: object): boolean {
	return ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'].some((member) => member in key)
}

function jwtSecretBytes(secret: string | Uint8Array): Uint8Array {
	const bytes = typeof secret === 'string' ? textToBytes(secret) : secret
	if (bytes.byteLength < minimumJwtHmacSecretBytes) {
		throw new Error(
			`@goobits/security/jwt: HMAC secret must contain at least ${minimumJwtHmacSecretBytes} bytes`
		)
	}
	return bytes
}

function positiveLifetime(value: number): number {
	if (!Number.isSafeInteger(value) || value <= 0) {
		throw new Error('@goobits/security/jwt: numeric expiration must be positive')
	}
	return value
}

function requiredText(value: string, label: string): string {
	if (!value.trim()) throw new Error(`@goobits/security/jwt: ${label} is required`)
	return value
}
