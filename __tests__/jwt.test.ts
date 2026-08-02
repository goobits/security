import { decodeProtectedHeader, exportJWK, generateKeyPair, SignJWT } from 'jose'
import { describe, expect, it } from 'vitest'

import { signJwt, verifyJwt, verifyJwtWithJwks } from '../src/jwt.js'

const secret = 'test-secret-not-for-production-use-min-32-chars-long'

describe('shared JWT primitive', () => {
	it('issues and verifies purpose-bound JWTs with pinned claims', async () => {
		const token = await signJwt(
			{ roomId: 'connection-1', purpose: 'wormhole-transfer' },
			{
				secret,
				expiresIn: 60,
				audience: 'goobits:tunnel',
				issuer: 'goobits:switchboard',
				subject: 'participant:user-1',
				jwtId: 'token-1',
				type: 'goobits-tunnel+jwt'
			}
		)

		expect(decodeProtectedHeader(token)).toEqual({
			alg: 'HS256',
			typ: 'goobits-tunnel+jwt'
		})
		await expect(
			verifyJwt(token, {
				secret,
				audience: 'goobits:tunnel',
				issuer: 'goobits:switchboard',
				type: 'goobits-tunnel+jwt',
				requiredClaims: ['sub', 'jti']
			})
		).resolves.toMatchObject({
			ok: true,
			payload: {
				roomId: 'connection-1',
				purpose: 'wormhole-transfer',
				sub: 'participant:user-1',
				jti: 'token-1'
			}
		})
	})

	it('rejects the wrong audience, type, and weak secrets', async () => {
		const token = await signJwt(
			{ roomId: 'connection-1' },
			{
				secret,
				expiresIn: 60,
				audience: 'goobits:tunnel',
				type: 'goobits-tunnel+jwt'
			}
		)

		await expect(
			verifyJwt(token, {
				secret,
				audience: 'another-audience',
				type: 'goobits-tunnel+jwt'
			})
		).resolves.toEqual({ ok: false, reason: 'invalid' })
		await expect(
			verifyJwt(token, {
				secret,
				audience: 'goobits:tunnel',
				type: 'another-type'
			})
		).resolves.toEqual({ ok: false, reason: 'invalid' })
		await expect(signJwt({}, { secret: 'weak', expiresIn: 60 })).rejects.toThrow(
			'at least 32 bytes'
		)
	})

	it('distinguishes expiration while keeping other verification failures opaque', async () => {
		const token = await signJwt(
			{ roomId: 'connection-1' },
			{
				secret,
				expiresIn: 60,
				algorithm: 'HS384',
				issuedAt: 1_700_000_000
			}
		)

		await expect(
			verifyJwt(token, {
				secret,
				algorithms: ['HS384'],
				currentDate: new Date(1_700_000_061_000)
			})
		).resolves.toEqual({ ok: false, reason: 'expired' })
		await expect(
			verifyJwt(token, {
				secret,
				algorithms: ['HS256'],
				currentDate: new Date(1_700_000_001_000)
			})
		).resolves.toEqual({ ok: false, reason: 'invalid' })
	})
})

describe('static JWKS JWT verification', () => {
	async function signedToken(overrides: Record<string, unknown> = {}) {
		const { privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true })
		const publicJwk = await exportJWK(publicKey)
		publicJwk.kid = 'provider-key-1'
		publicJwk.use = 'sig'
		publicJwk.alg = 'RS256'
		const token = await new SignJWT({ email: 'person@example.test', ...overrides })
			.setProtectedHeader({ alg: 'RS256', kid: publicJwk.kid, typ: 'JWT' })
			.setIssuer('https://issuer.example.test')
			.setAudience('client-123')
			.setSubject('provider-subject-1')
			.setIssuedAt(1_700_000_000)
			.setExpirationTime(1_700_000_060)
			.sign(privateKey)
		return { publicJwk, token }
	}

	it('verifies a provider token with a bounded public key set and pinned claims', async () => {
		const { publicJwk, token } = await signedToken()

		await expect(
			verifyJwtWithJwks(token, {
				jwks: { keys: [publicJwk] },
				algorithms: ['RS256'],
				issuer: 'https://issuer.example.test',
				audience: 'client-123',
				type: 'JWT',
				requiredClaims: ['iss', 'aud', 'sub', 'iat', 'exp'],
				currentDate: new Date(1_700_000_030_000)
			})
		).resolves.toMatchObject({
			ok: true,
			payload: { sub: 'provider-subject-1', email: 'person@example.test' }
		})
	})

	it('rejects mismatched algorithms, issuers, audiences, and required claims', async () => {
		const { publicJwk, token } = await signedToken()
		const base = {
			jwks: { keys: [publicJwk] },
			algorithms: ['RS256'] as const,
			issuer: 'https://issuer.example.test',
			audience: 'client-123',
			requiredClaims: ['iss', 'aud', 'sub', 'iat', 'exp'] as const,
			currentDate: new Date(1_700_000_030_000)
		}

		await expect(verifyJwtWithJwks(token, { ...base, algorithms: ['ES256'] })).resolves.toEqual({
			ok: false,
			reason: 'invalid'
		})
		await expect(
			verifyJwtWithJwks(token, { ...base, issuer: 'https://other.example.test' })
		).resolves.toEqual({ ok: false, reason: 'invalid' })
		await expect(verifyJwtWithJwks(token, { ...base, audience: 'other-client' })).resolves.toEqual({
			ok: false,
			reason: 'invalid'
		})
		await expect(
			verifyJwtWithJwks(token, { ...base, requiredClaims: [...base.requiredClaims, 'nonce'] })
		).resolves.toEqual({ ok: false, reason: 'invalid' })
	})

	it('distinguishes expiry and rejects private, symmetric, duplicate, and oversized key sets', async () => {
		const { publicJwk, token } = await signedToken()
		const base = {
			algorithms: ['RS256'] as const,
			issuer: 'https://issuer.example.test',
			audience: 'client-123',
			requiredClaims: ['iss', 'aud', 'sub', 'iat', 'exp'] as const,
			currentDate: new Date(1_700_000_061_000)
		}

		await expect(
			verifyJwtWithJwks(token, { ...base, jwks: { keys: [publicJwk] } })
		).resolves.toEqual({
			ok: false,
			reason: 'expired'
		})
		await expect(
			verifyJwtWithJwks(token, {
				...base,
				jwks: { keys: [{ ...publicJwk, d: 'private-material' }] }
			})
		).resolves.toEqual({ ok: false, reason: 'invalid' })
		await expect(
			verifyJwtWithJwks(token, {
				...base,
				jwks: { keys: [{ kty: 'oct', k: 'symmetric-material', kid: 'provider-key-1' }] }
			})
		).resolves.toEqual({ ok: false, reason: 'invalid' })
		await expect(
			verifyJwtWithJwks(token, { ...base, jwks: { keys: [publicJwk, { ...publicJwk }] } })
		).resolves.toEqual({ ok: false, reason: 'invalid' })
		await expect(
			verifyJwtWithJwks(token, {
				...base,
				jwks: {
					keys: Array.from({ length: 101 }, (_, index) => ({ ...publicJwk, kid: `key-${index}` }))
				}
			})
		).resolves.toEqual({ ok: false, reason: 'invalid' })
	})

	it('rejects unsafe verifier configuration before reading the key set', async () => {
		const { token } = await signedToken()

		await expect(
			verifyJwtWithJwks(token, {
				jwks: { keys: [] },
				algorithms: [],
				issuer: 'https://issuer.example.test',
				audience: 'client-123',
				requiredClaims: ['sub']
			})
		).rejects.toThrow('at least one JWKS algorithm')
	})
})
