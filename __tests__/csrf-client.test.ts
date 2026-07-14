import { describe, expect, it, vi } from 'vitest'

import { createCsrfFetch, isSameOriginRequest, readBrowserCookie } from '../src/csrfClient.js'

function createFetchSpy() {
	const calls: Array<[RequestInfo | URL, RequestInit | undefined]> = []
	const fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
		calls.push([input, init])
		return new Response(null, { status: 204 })
	})
	return { calls, fetch }
}

describe('csrf client helpers', () => {
	it('reads encoded browser cookie values', () => {
		expect(readBrowserCookie('csrf-token', 'other=1; csrf-token=a%20b%2Fc')).toBe('a b/c')
		expect(readBrowserCookie('missing', 'csrf-token=token')).toBe(null)
	})

	it('detects same-origin requests against a base URL', () => {
		expect(isSameOriginRequest('/api/test', 'https://example.test/page')).toBe(true)
		expect(isSameOriginRequest('https://example.test/api/test', 'https://example.test/page')).toBe(
			true
		)
		expect(
			isSameOriginRequest('https://elsewhere.test/api/test', 'https://example.test/page')
		).toBe(false)
	})

	it('adds the CSRF header to unsafe same-origin requests', async () => {
		const { calls, fetch } = createFetchSpy()
		const csrfFetch = createCsrfFetch({
			baseUrl: 'https://example.test/page',
			fetch,
			readToken: () => 'token-1'
		})

		await csrfFetch('/api/test', { method: 'POST' })

		const headers = calls[0]?.[1]?.headers
		expect(headers).toBeInstanceOf(Headers)
		expect((headers as Headers).get('X-CSRF-Token')).toBe('token-1')
	})

	it('skips safe, cross-origin, and explicitly supplied headers', async () => {
		const { calls, fetch } = createFetchSpy()
		const csrfFetch = createCsrfFetch({
			baseUrl: 'https://example.test/page',
			fetch,
			readToken: () => 'token-1'
		})

		await csrfFetch('/api/test', { method: 'GET' })
		await csrfFetch('https://elsewhere.test/api/test', { method: 'POST' })
		await csrfFetch('/api/test', {
			method: 'POST',
			headers: { 'X-CSRF-Token': 'caller-token' }
		})

		expect((calls[0]?.[1]?.headers as Headers).get('X-CSRF-Token')).toBe(null)
		expect((calls[1]?.[1]?.headers as Headers).get('X-CSRF-Token')).toBe(null)
		expect((calls[2]?.[1]?.headers as Headers).get('X-CSRF-Token')).toBe('caller-token')
	})
})
