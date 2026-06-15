import { SignJWT } from 'jose'
import { describe, expect, it } from 'vitest'

import { createAdminAuth, generateAdminApiKey } from '../src/adminAuth.js'
import { toBytes } from '../src/_internal/crypto.js'

const SECRET = 'test-secret-not-for-production-use-min-32-chars-long'

function makeRequest(headers: Record<string, string>): Request {
	return new Request('https://example.test/admin', { headers })
}

describe('createAdminAuth', () => {
	it('throws when jwtSecret is empty', () => {
		expect(() => createAdminAuth({ jwtSecret: '' })).toThrow(/jwtSecret/)
	})

	it('throws when jwtSecret is too short', () => {
		expect(() => createAdminAuth({ jwtSecret: 'short' })).toThrow(/at least 32/)
	})

	it('issues + verifies an admin JWT', async () => {
		const adminAuth = createAdminAuth({ jwtSecret: SECRET })
		const token = await adminAuth.createAdminToken({ id: 'user-1', role: 'admin' })
		const request = makeRequest({ authorization: `Bearer ${ token }` })
		const result = await adminAuth.requireAdmin(request)

		expect(result.authenticated).toBe(true)
		if (result.authenticated) {
			expect(result.user.id).toBe('user-1')
			expect(result.method).toBe('jwt')
		}
	})

	it('rejects tokens lacking admin claim', async () => {
		const adminAuth = createAdminAuth({ jwtSecret: SECRET })
		const nonAdminToken = await new SignJWT({ id: 'user-1', role: 'reader' })
			.setProtectedHeader({ alg: 'HS256' })
			.setExpirationTime('1h')
			.sign(toBytes(SECRET))
		const request = makeRequest({ authorization: `Bearer ${ nonAdminToken }` })
		const result = await adminAuth.requireAdmin(request)

		expect(result.authenticated).toBe(false)
		if (!result.authenticated) expect(result.reason).toBe('invalid-jwt')
	})

	it('rejects malformed bearer tokens', async () => {
		const adminAuth = createAdminAuth({ jwtSecret: SECRET })
		const request = makeRequest({ authorization: 'Bearer not.a.jwt' })
		const result = await adminAuth.requireAdmin(request)
		expect(result.authenticated).toBe(false)
	})

	it('rejects tokens signed with a different algorithm', async () => {
		const adminAuth = createAdminAuth({ jwtSecret: SECRET, algorithms: [ 'HS256' ] })
		// Forge a token with HS512 — should be rejected because only HS256 is allowed
		const hs512Token = await new SignJWT({ id: 'user-1', role: 'admin' })
			.setProtectedHeader({ alg: 'HS512' })
			.setExpirationTime('1h')
			.sign(toBytes(SECRET))
		const request = makeRequest({ authorization: `Bearer ${ hs512Token }` })
		const result = await adminAuth.requireAdmin(request)
		expect(result.authenticated).toBe(false)
	})

	it('rejects expired tokens', async () => {
		const adminAuth = createAdminAuth({ jwtSecret: SECRET })
		const expiredToken = await new SignJWT({ id: 'user-1', role: 'admin' })
			.setProtectedHeader({ alg: 'HS256' })
			.setExpirationTime(Math.floor(Date.now() / 1000) - 10) // 10s ago
			.sign(toBytes(SECRET))
		const request = makeRequest({ authorization: `Bearer ${ expiredToken }` })
		const result = await adminAuth.requireAdmin(request)
		expect(result.authenticated).toBe(false)
	})

	it('accepts API key when configured', async () => {
		const apiKey = generateAdminApiKey()
		const adminAuth = createAdminAuth({ jwtSecret: SECRET, apiKey })
		const request = makeRequest({ 'x-admin-api-key': apiKey })
		const result = await adminAuth.requireAdmin(request)

		expect(result.authenticated).toBe(true)
		if (result.authenticated) expect(result.method).toBe('apikey')
	})

	it('rejects wrong API key (constant-time comparison)', async () => {
		const apiKey = generateAdminApiKey()
		const adminAuth = createAdminAuth({ jwtSecret: SECRET, apiKey })
		const request = makeRequest({ 'x-admin-api-key': generateAdminApiKey() })
		const result = await adminAuth.requireAdmin(request)

		expect(result.authenticated).toBe(false)
		if (!result.authenticated) expect(result.reason).toBe('invalid-apikey')
	})

	it('reports missing reason when no credentials are presented', async () => {
		const adminAuth = createAdminAuth({ jwtSecret: SECRET })
		const result = await adminAuth.requireAdmin(makeRequest({}))
		expect(result.authenticated).toBe(false)
		if (!result.authenticated) expect(result.reason).toBe('missing')
	})
})

describe('createAdminAuth — numeric tokenTtl (regression: jose absolute-vs-relative)', () => {
	it('numeric tokenTtl is treated as RELATIVE seconds, not absolute UNIX seconds', async () => {
		const adminAuth = createAdminAuth({ jwtSecret: SECRET, tokenTtl: 3600 }) // 1 hour
		const token = await adminAuth.createAdminToken({ id: 'user-1', role: 'admin' })
		const request = makeRequest({ authorization: `Bearer ${ token }` })
		const result = await adminAuth.requireAdmin(request)
		// If jose's absolute-seconds semantics leaked through, the token would
		// claim exp=3600 (epoch second ≈ Jan 1970) and verification would fail
		// as expired. We expect a fresh, valid token.
		expect(result.authenticated).toBe(true)
	})

	it('overrideTtl numeric value is also treated as relative seconds', async () => {
		const adminAuth = createAdminAuth({ jwtSecret: SECRET })
		const token = await adminAuth.createAdminToken({ id: 'user-1', role: 'admin' }, 7200)
		const request = makeRequest({ authorization: `Bearer ${ token }` })
		const result = await adminAuth.requireAdmin(request)
		expect(result.authenticated).toBe(true)
	})
})

describe('createAdminAuth — audience / issuer / clockTolerance', () => {
	it('rejects tokens with mismatched audience', async () => {
		const issuer = createAdminAuth({ jwtSecret: SECRET, audience: 'app-a' })
		const verifier = createAdminAuth({ jwtSecret: SECRET, audience: 'app-b' })
		const token = await issuer.createAdminToken({ id: 'user-1', role: 'admin' })
		const result = await verifier.requireAdmin(makeRequest({ authorization: `Bearer ${ token }` }))
		expect(result.authenticated).toBe(false)
	})

	it('accepts tokens with matching audience', async () => {
		const adminAuth = createAdminAuth({ jwtSecret: SECRET, audience: 'app-a' })
		const token = await adminAuth.createAdminToken({ id: 'user-1', role: 'admin' })
		const result = await adminAuth.requireAdmin(makeRequest({ authorization: `Bearer ${ token }` }))
		expect(result.authenticated).toBe(true)
	})

	it('rejects tokens with mismatched issuer', async () => {
		const issuer = createAdminAuth({ jwtSecret: SECRET, issuer: 'svc-a' })
		const verifier = createAdminAuth({ jwtSecret: SECRET, issuer: 'svc-b' })
		const token = await issuer.createAdminToken({ id: 'user-1', role: 'admin' })
		const result = await verifier.requireAdmin(makeRequest({ authorization: `Bearer ${ token }` }))
		expect(result.authenticated).toBe(false)
	})

	it('throws when algorithms array is empty', () => {
		expect(() => createAdminAuth({ jwtSecret: SECRET, algorithms: [] })).toThrow(/algorithms/)
	})
})

describe('generateAdminApiKey', () => {
	it('returns a 64-char hex string (256 bits)', () => {
		const key = generateAdminApiKey()
		expect(key).toMatch(/^[0-9a-f]{64}$/)
	})

	it('returns distinct keys on successive calls', () => {
		expect(generateAdminApiKey()).not.toBe(generateAdminApiKey())
	})
})
