import { describe, expect, it } from 'vitest'

import { createCsrf } from '../src/MemoryCsrfStore.js'

function makeRequest(headers: Record<string, string>): Request {
	return new Request('https://example.test/api', { headers })
}

function makeResponse(): Response {
	return new Response('OK')
}

describe('createCsrf', () => {
	it('generates a 64-char hex token', async () => {
		const csrf = createCsrf()
		const token = await csrf.generate()
		expect(token).toMatch(/^[0-9a-f]{64}$/)
	})

	it('sets the cookie + header in setCookie', async () => {
		const csrf = createCsrf()
		const response = makeResponse()
		const token = await csrf.generate({ trackExpiry: false })
		csrf.setCookie(response, token)
		expect(response.headers.get('Set-Cookie')).toContain(`csrf-token=${ token }`)
		expect(response.headers.get('X-CSRF-Token')).toBe(token)
	})

	it('validates matching cookie + header', async () => {
		const csrf = createCsrf()
		const token = await csrf.generate({ trackExpiry: false })
		const request = makeRequest({
			cookie: `csrf-token=${ token }`,
			'X-CSRF-Token': token
		})
		expect(await csrf.validate(request)).toBe(true)
	})

	it('rejects when cookie missing', async () => {
		const csrf = createCsrf()
		const request = makeRequest({ 'X-CSRF-Token': 'abc' })
		expect(await csrf.validate(request)).toBe(false)
	})

	it('rejects when header missing', async () => {
		const csrf = createCsrf()
		const request = makeRequest({ cookie: 'csrf-token=abc' })
		expect(await csrf.validate(request)).toBe(false)
	})

	it('rejects mismatched cookie/header (constant-time comparison)', async () => {
		const csrf = createCsrf()
		const request = makeRequest({
			cookie: 'csrf-token=aaaa',
			'X-CSRF-Token': 'bbbb'
		})
		expect(await csrf.validate(request)).toBe(false)
	})

	it('tracks store size when trackExpiry is on', async () => {
		const csrf = createCsrf()
		await csrf.generate()
		await csrf.generate()
		expect(csrf.storeSize).toBe(2)
	})

	it('rejects expired tokens when checkExpiry is true', async () => {
		const csrf = createCsrf({
			tokenStore: {
				get() { return Date.now() - 1 },
				set() {},
				delete() {},
				clear() {}
			}
		})
		const token = await csrf.generate({ trackExpiry: false })
		const request = makeRequest({
			cookie: `csrf-token=${ token }`,
			'X-CSRF-Token': token
		})
		expect(await csrf.validate(request, { checkExpiry: true })).toBe(false)
	})

	it('rejects tokens missing from the store when checkExpiry is true', async () => {
		const csrf = createCsrf()
		const token = await csrf.generate({ trackExpiry: false })
		const request = makeRequest({
			cookie: `csrf-token=${ token }`,
			'X-CSRF-Token': token
		})

		expect(await csrf.validate(request, { checkExpiry: true })).toBe(false)
	})

	it('allows expired tokens when checkExpiry is false (default)', async () => {
		const csrf = createCsrf({
			tokenStore: {
				get() { return Date.now() - 1 },
				set() {},
				delete() {},
				clear() {}
			}
		})
		const token = await csrf.generate({ trackExpiry: false })
		const request = makeRequest({
			cookie: `csrf-token=${ token }`,
			'X-CSRF-Token': token
		})
		expect(await csrf.validate(request)).toBe(true)
	})

	it('clear empties the store', async () => {
		const csrf = createCsrf()
		await csrf.generate()
		await csrf.generate()
		expect(csrf.storeSize).toBe(2)
		await csrf.clear()
		expect(csrf.storeSize).toBe(0)
	})

	it('respects custom cookie + header names', async () => {
		const csrf = createCsrf({ cookieName: 'my_csrf', headerName: 'My-CSRF' })
		expect(csrf.cookieName).toBe('my_csrf')
		expect(csrf.headerName).toBe('My-CSRF')
		const token = await csrf.generate()
		const response = makeResponse()
		csrf.setCookie(response, token)
		expect(response.headers.get('Set-Cookie')).toContain(`my_csrf=${ token }`)
		expect(response.headers.get('My-CSRF')).toBe(token)
	})

	it('fails open on store read errors by default', async () => {
		const token = 'a'.repeat(64)
		const csrf = createCsrf({
			tokenStore: {
				get() { throw new Error('store down') },
				set() {},
				delete() {},
				clear() {}
			}
		})
		const request = makeRequest({
			cookie: `csrf-token=${ token }`,
			'X-CSRF-Token': token
		})

		expect(await csrf.validate(request, { checkExpiry: true })).toBe(true)
	})

	it('fails closed on store read errors when configured', async () => {
		const token = 'a'.repeat(64)
		const csrf = createCsrf({
			failClosed: true,
			tokenStore: {
				get() { throw new Error('store down') },
				set() {},
				delete() {},
				clear() {}
			}
		})
		const request = makeRequest({
			cookie: `csrf-token=${ token }`,
			'X-CSRF-Token': token
		})

		expect(await csrf.validate(request, { checkExpiry: true })).toBe(false)
	})

	it('surfaces store write errors during token generation', async () => {
		const csrf = createCsrf({
			tokenStore: {
				get() { return undefined },
				set() { throw new Error('store down') },
				delete() {},
				clear() {}
			}
		})

		await expect(csrf.generate()).rejects.toThrow('store down')
	})
})
