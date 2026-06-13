import { SignJWT } from 'jose'
import { describe, expect, it } from 'vitest'

import { toBytes } from '../src/_internal/crypto.js'
import { createPrincipalAuth } from '../src/principal-auth.js'

const SECRET = 'test-secret-not-for-production-use-min-32-chars-long'

function makeRequest(headers: Record<string, string>): Request {
	return new Request('https://example.test/api', { headers })
}

describe('createPrincipalAuth', () => {
	it('issues and verifies principal JWTs', async () => {
		const auth = createPrincipalAuth({ jwtSecret: SECRET, audience: 'app-a', issuer: 'issuer-a' })
		const token = await auth.createPrincipalToken({ id: 'user-1', roles: [ 'editor' ] })
		const result = await auth.requirePrincipal(makeRequest({ authorization: `Bearer ${ token }` }))

		expect(result.authenticated).toBe(true)
		if (result.authenticated) {
			expect(result.principal.id).toBe('user-1')
			expect(result.principal.roles).toEqual([ 'editor' ])
			expect(result.method).toBe('jwt')
		}
	})

	it('rejects tokens with wrong issuer or audience', async () => {
		const issuer = createPrincipalAuth({ jwtSecret: SECRET, audience: 'app-a', issuer: 'issuer-a' })
		const verifier = createPrincipalAuth({ jwtSecret: SECRET, audience: 'app-b', issuer: 'issuer-a' })
		const token = await issuer.createPrincipalToken({ id: 'user-1' })

		const result = await verifier.requirePrincipal(makeRequest({ authorization: `Bearer ${ token }` }))
		expect(result).toEqual({ authenticated: false, reason: 'invalid-jwt' })
	})

	it('rejects malformed and missing JWT principals', async () => {
		const auth = createPrincipalAuth({ jwtSecret: SECRET })
		const malformed = await new SignJWT({ role: 'reader' })
			.setProtectedHeader({ alg: 'HS256' })
			.setExpirationTime('1h')
			.sign(toBytes(SECRET))

		await expect(auth.requirePrincipal(makeRequest({ authorization: 'Bearer not.a.jwt' })))
			.resolves.toEqual({ authenticated: false, reason: 'invalid-jwt' })
		await expect(auth.requirePrincipal(makeRequest({ authorization: `Bearer ${ malformed }` })))
			.resolves.toEqual({ authenticated: false, reason: 'invalid-jwt' })
	})

	it('authenticates mapped API keys', async () => {
		const auth = createPrincipalAuth({
			jwtSecret: SECRET,
			apiKeys: [
				{ key: 'machine-key-a', principal: { id: 'service-a', roles: [ 'service' ] } }
			]
		})

		const result = await auth.requirePrincipal(makeRequest({ 'x-api-key': 'machine-key-a' }))
		expect(result.authenticated).toBe(true)
		if (result.authenticated) {
			expect(result.principal.id).toBe('service-a')
			expect(result.method).toBe('apikey')
		}
	})

	it('supports a custom API key header', async () => {
		const auth = createPrincipalAuth({
			jwtSecret: SECRET,
			apiKeyHeader: 'x-service-key',
			apiKeys: [
				{ key: 'machine-key-a', principal: { id: 'service-a' } }
			]
		})

		const result = await auth.requirePrincipal(makeRequest({ 'x-service-key': 'machine-key-a' }))
		expect(result.authenticated).toBe(true)
	})

	it('runs an optional principal authorization gate', async () => {
		const auth = createPrincipalAuth({
			jwtSecret: SECRET,
			authorizePrincipal: principal => principal.id === 'allowed'
		})
		const token = await auth.createPrincipalToken({ id: 'blocked' })

		const result = await auth.requirePrincipal(makeRequest({ authorization: `Bearer ${ token }` }))
		expect(result).toEqual({ authenticated: false, reason: 'forbidden' })
	})

	it('treats numeric token TTL as relative seconds', async () => {
		const auth = createPrincipalAuth({ jwtSecret: SECRET, tokenTtl: 3600 })
		const token = await auth.createPrincipalToken({ id: 'user-1' })

		const result = await auth.requirePrincipal(makeRequest({ authorization: `Bearer ${ token }` }))
		expect(result.authenticated).toBe(true)
	})

	it('reports missing when no credentials are presented', async () => {
		const auth = createPrincipalAuth({ jwtSecret: SECRET })
		await expect(auth.requirePrincipal(makeRequest({}))).resolves.toEqual({
			authenticated: false,
			reason: 'missing'
		})
	})
})
