import { decodeProtectedHeader } from 'jose'
import { describe, expect, it } from 'vitest'

import { signJwt, verifyJwt } from '../src/jwt.js'

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
