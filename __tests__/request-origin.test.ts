import { describe, expect, it } from 'vitest'

import { verifyRequestOrigin } from '../src/requestOrigin.js'

const requestUrl = new URL('https://bandamp.org/account')

function verify(headers: HeadersInit = {}, options: { allowMissingBrowserContext?: boolean } = {}) {
	return verifyRequestOrigin({
		request: new Request(requestUrl, { method: 'POST', headers }),
		requestUrl,
		allowedOrigins: ['https://bandamp.org', 'https://www.bandamp.org'],
		...options
	})
}

describe('verifyRequestOrigin', () => {
	it('allows safe methods without browser context', () => {
		expect(
			verifyRequestOrigin({
				request: new Request(requestUrl),
				requestUrl,
				allowedOrigins: []
			})
		).toEqual({ ok: true })
	})

	it('accepts an explicitly allowed Origin or Referer', () => {
		expect(verify({ origin: 'https://www.bandamp.org' })).toEqual({ ok: true })
		expect(verify({ referer: 'https://bandamp.org/account/profile' })).toEqual({ ok: true })
	})

	it('rejects cross-site and mismatched origins', () => {
		expect(verify({ 'sec-fetch-site': 'cross-site', origin: 'https://bandamp.org' })).toEqual({
			ok: false,
			reason: 'cross-site'
		})
		expect(verify({ origin: 'https://evil.example' })).toEqual({
			ok: false,
			reason: 'origin-mismatch'
		})
	})

	it('rejects malformed, oversized, and missing browser context', () => {
		expect(verify({ origin: 'null' })).toEqual({ ok: false, reason: 'invalid-origin' })
		expect(verify({ referer: `https://bandamp.org/${'x'.repeat(2_100)}` })).toEqual({
			ok: false,
			reason: 'invalid-referer'
		})
		expect(verify()).toEqual({ ok: false, reason: 'missing-browser-context' })
	})

	it('allows missing browser context only through explicit policy', () => {
		expect(verify({}, { allowMissingBrowserContext: true })).toEqual({ ok: true })
	})
})
