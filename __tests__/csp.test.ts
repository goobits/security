import { describe, expect, it } from 'vitest'

import { buildCsp, buildCspHeader, createCspDirectives, createCspNonce } from '../src/csp.js'

describe('createCspDirectives', () => {
	it('emits a production baseline', () => {
		const d = createCspDirectives({ mode: 'production' })
		expect(d['default-src']).toEqual(["'self'"])
		expect(d['script-src']).toEqual(["'self'"])
		expect(d['frame-ancestors']).toEqual(["'none'"])
		expect(d['object-src']).toEqual(["'none'"])
		// upgrade-insecure-requests is a flag directive with no values.
		expect(d['upgrade-insecure-requests']).toEqual([])
	})

	it('relaxes script-src in development for HMR', () => {
		const d = createCspDirectives({ mode: 'development' })
		expect(d['script-src']).toContain("'unsafe-eval'")
		expect(d['script-src']).toContain("'unsafe-inline'")
	})

	it('merges extra sources into baseline', () => {
		const d = createCspDirectives({
			mode: 'production',
			extraSources: {
				'script-src': ['https://js.stripe.com'],
				'connect-src': ['https://api.stripe.com']
			}
		})
		expect(d['script-src']).toEqual(["'self'", 'https://js.stripe.com'])
		expect(d['connect-src']).toEqual(["'self'", 'https://api.stripe.com'])
	})

	it('dedupes overlapping sources', () => {
		const d = createCspDirectives({
			mode: 'production',
			extraSources: { 'script-src': ["'self'", "'self'", 'https://x.com'] }
		})
		expect(d['script-src']).toEqual(["'self'", 'https://x.com'])
	})

	it('adds nonce to script-src and style-src', () => {
		const d = createCspDirectives({ nonce: 'abc123' })
		expect(d['script-src']).toContain("'nonce-abc123'")
		expect(d['style-src']).toContain("'nonce-abc123'")
	})

	it('drops frame-ancestors when allowFraming=true', () => {
		const d = createCspDirectives({ allowFraming: true })
		expect(d['frame-ancestors']).toBeUndefined()
	})

	it('attaches report-uri and report-to', () => {
		const d = createCspDirectives({
			reportUri: 'https://csp.example/report',
			reportTo: 'csp-endpoint'
		})
		expect(d['report-uri']).toEqual(['https://csp.example/report'])
		expect(d['report-to']).toEqual(['csp-endpoint'])
	})
})

describe('buildCspHeader', () => {
	it('serializes directive map into header value', () => {
		const header = buildCspHeader({
			'default-src': ["'self'"],
			'script-src': ["'self'", 'https://x.com']
		})
		expect(header).toBe("default-src 'self'; script-src 'self' https://x.com")
	})

	it('emits flag directives without values', () => {
		const header = buildCspHeader({ 'upgrade-insecure-requests': [] })
		expect(header).toBe('upgrade-insecure-requests')
	})
})

describe('buildCsp', () => {
	it('one-shot: build directives + serialize', () => {
		const header = buildCsp({
			mode: 'production',
			extraSources: { 'script-src': ['https://js.stripe.com'] }
		})
		expect(header).toContain("script-src 'self' https://js.stripe.com")
	})
})

describe('createCspNonce', () => {
	it('returns a URL-safe base64 string of the expected length', () => {
		const nonce = createCspNonce()
		expect(nonce).toMatch(/^[A-Za-z0-9_-]{20,32}$/)
	})

	it('returns distinct nonces on successive calls', () => {
		const a = createCspNonce()
		const b = createCspNonce()
		expect(a).not.toBe(b)
	})
})
