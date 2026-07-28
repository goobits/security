import { errors, jwtVerify, SignJWT, type JWTPayload } from 'jose'

import { textToBytes } from './crypto/encoding.js'

/** HMAC algorithms supported by the shared JWT primitive. */
export type JwtHmacAlgorithm = 'HS256' | 'HS384' | 'HS512'

/** Options for issuing a short-lived, purpose-bound JWT. */
export type SignJwtOptions = {
	secret: string | Uint8Array
	expiresIn: string | number
	algorithm?: JwtHmacAlgorithm
	audience?: string | string[]
	issuer?: string
	subject?: string
	jwtId?: string
	type?: string
	issuedAt?: number
}

/** Options for verifying a purpose-bound JWT with a pinned algorithm. */
export type VerifyJwtOptions = {
	secret: string | Uint8Array
	algorithms?: readonly JwtHmacAlgorithm[]
	audience?: string | string[]
	issuer?: string | string[]
	type?: string
	clockTolerance?: number
	currentDate?: Date
	requiredClaims?: string[]
}

/** Result of JWT verification without leaking JOSE implementation errors. */
export type JwtVerification =
	| { ok: true; payload: JWTPayload }
	| { ok: false; reason: 'expired' | 'invalid' }

const minimumJwtHmacSecretBytes = 32

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
	try {
		const { payload, protectedHeader } = await jwtVerify(
			requiredText(token, 'JWT'),
			jwtSecretBytes(options.secret),
			{
				algorithms: [...(options.algorithms ?? ['HS256'])],
				...(options.audience === undefined ? {} : { audience: options.audience }),
				...(options.issuer === undefined ? {} : { issuer: options.issuer }),
				...(options.clockTolerance === undefined
					? {}
					: { clockTolerance: options.clockTolerance }),
				...(options.currentDate === undefined ? {} : { currentDate: options.currentDate }),
				...(options.requiredClaims === undefined
					? {}
					: { requiredClaims: options.requiredClaims })
			}
		)
		if (options.type !== undefined && protectedHeader.typ !== options.type) {
			return { ok: false, reason: 'invalid' }
		}
		return { ok: true, payload }
	} catch (error) {
		return {
			ok: false,
			reason: error instanceof errors.JWTExpired ? 'expired' : 'invalid'
		}
	}
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
