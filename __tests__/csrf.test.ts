import { describe, expect, it } from 'vitest'

import { createCsrf, MemoryCsrfStore } from '../src/csrf.js'

const SECRET = 'csrf-test-secret-that-is-at-least-32-bytes'
const SESSION_BINDING = 'session-123'

function makeRequest(headers: Record<string, string>): Request {
	return new Request('https://example.test/api', { headers })
}

function protectedRequest(token: string): Request {
	return makeRequest({
		cookie: `csrf-token=${token}`,
		'X-CSRF-Token': token
	})
}

function makeResponse(): Response {
	return new Response('OK')
}

describe('createCsrf', () => {
	it('requires a strong shared signing secret', () => {
		expect(() => createCsrf({ secret: 'weak' })).toThrowError(/at least 32 bytes/)
	})

	it('generates a signed token bound to the current session', async () => {
		const csrf = createCsrf({ secret: SECRET })
		const token = await csrf.generate({ sessionBinding: SESSION_BINDING })

		expect(token).toMatch(/^v1\.[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}$/u)
		expect(await csrf.validate(protectedRequest(token), { sessionBinding: SESSION_BINDING })).toBe(
			true
		)
	})

	it('rejects replay under another session binding', async () => {
		const csrf = createCsrf({ secret: SECRET })
		const token = await csrf.generate({ sessionBinding: SESSION_BINDING, trackExpiry: false })

		expect(await csrf.validate(protectedRequest(token), { sessionBinding: 'session-456' })).toBe(
			false
		)
	})

	it('rejects attacker-selected and tampered matching tokens', async () => {
		const csrf = createCsrf({ secret: SECRET })
		const token = await csrf.generate({ sessionBinding: SESSION_BINDING, trackExpiry: false })
		const tampered = `${token.slice(0, -1)}${token.endsWith('a') ? 'b' : 'a'}`

		expect(
			await csrf.validate(protectedRequest('attacker-known-token'), {
				sessionBinding: SESSION_BINDING
			})
		).toBe(false)
		expect(
			await csrf.validate(protectedRequest(tampered), { sessionBinding: SESSION_BINDING })
		).toBe(false)
	})

	it('sets the cookie and header in setCookie', async () => {
		const csrf = createCsrf({ secret: SECRET })
		const response = makeResponse()
		const token = await csrf.generate({ sessionBinding: SESSION_BINDING, trackExpiry: false })
		csrf.setCookie(response, token)
		expect(response.headers.get('Set-Cookie')).toContain(`csrf-token=${token}`)
		expect(response.headers.get('X-CSRF-Token')).toBe(token)
	})

	it('rejects missing and mismatched double-submit values', async () => {
		const csrf = createCsrf({ secret: SECRET })
		const options = { sessionBinding: SESSION_BINDING }

		expect(await csrf.validate(makeRequest({ 'X-CSRF-Token': 'abc' }), options)).toBe(false)
		expect(await csrf.validate(makeRequest({ cookie: 'csrf-token=abc' }), options)).toBe(false)
		expect(
			await csrf.validate(
				makeRequest({ cookie: 'csrf-token=aaaa', 'X-CSRF-Token': 'bbbb' }),
				options
			)
		).toBe(false)
	})

	it('rejects empty and oversized session bindings', async () => {
		const csrf = createCsrf({ secret: SECRET })

		await expect(csrf.generate({ sessionBinding: '' })).rejects.toThrowError(/non-empty/)
		await expect(csrf.generate({ sessionBinding: 'a'.repeat(1_025) })).rejects.toThrowError(
			/not exceed 1024 bytes/
		)
	})

	it('tracks store size when trackExpiry is on', async () => {
		const csrf = createCsrf({ secret: SECRET })
		await csrf.generate({ sessionBinding: SESSION_BINDING })
		await csrf.generate({ sessionBinding: SESSION_BINDING })
		expect(csrf.storeSize).toBe(2)
	})

	it('bounds tracked tokens and evicts the oldest active token', () => {
		const store = new MemoryCsrfStore({ maxKeys: 2 })
		const expiresAt = Date.now() + 60_000
		store.set('oldest', expiresAt)
		store.set('newer', expiresAt)
		store.set('newest', expiresAt)

		expect(store.size).toBe(2)
		expect(store.get('oldest')).toBeUndefined()
		expect(store.get('newer')).toBe(expiresAt)
		expect(store.get('newest')).toBe(expiresAt)
	})

	it('cleans expired tokens before evicting active tokens at capacity', () => {
		const store = new MemoryCsrfStore({ maxKeys: 2 })
		store.set('expired', Date.now() - 1)
		store.set('active', Date.now() + 60_000)
		store.set('new', Date.now() + 60_000)

		expect(store.get('expired')).toBeUndefined()
		expect(store.get('active')).toBeDefined()
		expect(store.get('new')).toBeDefined()
	})

	it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])(
		'rejects invalid in-memory maxKeys %s',
		(maxKeys) => {
			expect(() => new MemoryCsrfStore({ maxKeys })).toThrowError(/positive safe integer/)
		}
	)

	it('rejects expired or untracked tokens when expiry checks are enabled', async () => {
		const expired = createCsrf({
			secret: SECRET,
			tokenStore: {
				get: () => Date.now() - 1,
				set() {},
				delete() {},
				clear() {}
			}
		})
		const expiredToken = await expired.generate({
			sessionBinding: SESSION_BINDING,
			trackExpiry: false
		})
		expect(
			await expired.validate(protectedRequest(expiredToken), {
				sessionBinding: SESSION_BINDING,
				checkExpiry: true
			})
		).toBe(false)

		const untracked = createCsrf({ secret: SECRET })
		const untrackedToken = await untracked.generate({
			sessionBinding: SESSION_BINDING,
			trackExpiry: false
		})
		expect(
			await untracked.validate(protectedRequest(untrackedToken), {
				sessionBinding: SESSION_BINDING,
				checkExpiry: true
			})
		).toBe(false)
	})

	it('uses cookie lifetime when expiry checks are disabled', async () => {
		const csrf = createCsrf({
			secret: SECRET,
			tokenStore: {
				get: () => Date.now() - 1,
				set() {},
				delete() {},
				clear() {}
			}
		})
		const token = await csrf.generate({ sessionBinding: SESSION_BINDING, trackExpiry: false })

		expect(
			await csrf.validate(protectedRequest(token), {
				sessionBinding: SESSION_BINDING,
				checkExpiry: false
			})
		).toBe(true)
	})

	it('clear empties the store', async () => {
		const csrf = createCsrf({ secret: SECRET })
		await csrf.generate({ sessionBinding: SESSION_BINDING })
		await csrf.generate({ sessionBinding: SESSION_BINDING })
		expect(csrf.storeSize).toBe(2)
		await csrf.clear()
		expect(csrf.storeSize).toBe(0)
	})

	it('respects custom cookie and header names', async () => {
		const csrf = createCsrf({
			secret: SECRET,
			cookieName: 'my_csrf',
			headerName: 'My-CSRF'
		})
		const token = await csrf.generate({ sessionBinding: SESSION_BINDING })
		const response = makeResponse()
		csrf.setCookie(response, token)

		expect(csrf.cookieName).toBe('my_csrf')
		expect(csrf.headerName).toBe('My-CSRF')
		expect(response.headers.get('Set-Cookie')).toContain(`my_csrf=${token}`)
		expect(response.headers.get('My-CSRF')).toBe(token)
	})

	it('fails closed on store read errors by default', async () => {
		const csrf = createCsrf({
			secret: SECRET,
			tokenStore: {
				get() {
					throw new Error('store down')
				},
				set() {},
				delete() {},
				clear() {}
			}
		})
		const token = await csrf.generate({ sessionBinding: SESSION_BINDING, trackExpiry: false })

		expect(
			await csrf.validate(protectedRequest(token), {
				sessionBinding: SESSION_BINDING,
				checkExpiry: true
			})
		).toBe(false)
	})

	it('allows an explicit fail-open policy for store read errors', async () => {
		const csrf = createCsrf({
			secret: SECRET,
			failClosed: false,
			tokenStore: {
				get() {
					throw new Error('store down')
				},
				set() {},
				delete() {},
				clear() {}
			}
		})
		const token = await csrf.generate({ sessionBinding: SESSION_BINDING, trackExpiry: false })

		expect(
			await csrf.validate(protectedRequest(token), {
				sessionBinding: SESSION_BINDING,
				checkExpiry: true
			})
		).toBe(true)
	})

	it('surfaces store write errors during token generation', async () => {
		const csrf = createCsrf({
			secret: SECRET,
			tokenStore: {
				get: () => undefined,
				set() {
					throw new Error('store down')
				},
				delete() {},
				clear() {}
			}
		})

		await expect(csrf.generate({ sessionBinding: SESSION_BINDING })).rejects.toThrow('store down')
	})
})
