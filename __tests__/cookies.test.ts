import { describe, expect, it } from 'vitest'

import { parseCookies, serializeCookie } from '../src/_internal/cookies.js'

describe('parseCookies', () => {
	it('returns empty object for missing header', () => {
		expect(parseCookies(null)).toEqual({})
		expect(parseCookies(undefined)).toEqual({})
		expect(parseCookies('')).toEqual({})
	})

	it('parses a simple cookie', () => {
		expect(parseCookies('foo=bar')).toEqual({ foo: 'bar' })
	})

	it('parses multiple cookies', () => {
		expect(parseCookies('a=1; b=2; c=3')).toEqual({ a: '1', b: '2', c: '3' })
	})

	it('trims whitespace around keys and values', () => {
		expect(parseCookies('  a = 1 ;  b=2')).toEqual({ a: '1', b: '2' })
	})
})

describe('serializeCookie', () => {
	it('serializes a simple cookie', () => {
		expect(serializeCookie('foo', 'bar')).toBe('foo=bar')
	})

	it('applies all options in the right order', () => {
		const expires = new Date('2026-01-01T00:00:00.000Z')
		const result = serializeCookie('csrf', 'abc123', {
			maxAge: 3600,
			expires,
			domain: 'example.test',
			path: '/api',
			sameSite: 'strict',
			httpOnly: true,
			secure: true
		})
		expect(result).toContain('csrf=abc123')
		expect(result).toContain('Max-Age=3600')
		expect(result).toContain(`Expires=${ expires.toUTCString() }`)
		expect(result).toContain('Domain=example.test')
		expect(result).toContain('Path=/api')
		expect(result).toContain('SameSite=Strict')
		expect(result).toContain('HttpOnly')
		expect(result).toContain('Secure')
	})

	it('throws on cookie name with illegal characters', () => {
		expect(() => serializeCookie('foo bar', 'x')).toThrow(/invalid cookie name/)
		expect(() => serializeCookie('foo;', 'x')).toThrow(/invalid cookie name/)
		expect(() => serializeCookie('foo=', 'x')).toThrow(/invalid cookie name/)
	})

	it('throws on cookie value with CRLF (header injection)', () => {
		expect(() => serializeCookie('x', 'value\r\nSet-Cookie: evil=1')).toThrow(/illegal characters/)
		expect(() => serializeCookie('x', 'a\nb')).toThrow(/illegal characters/)
	})

	it('throws on cookie value with separator characters', () => {
		expect(() => serializeCookie('x', 'a;b')).toThrow(/illegal characters/)
		expect(() => serializeCookie('x', 'a,b')).toThrow(/illegal characters/)
		expect(() => serializeCookie('x', 'a"b')).toThrow(/illegal characters/)
		expect(() => serializeCookie('x', 'a\\b')).toThrow(/illegal characters/)
		expect(() => serializeCookie('x', 'a b')).toThrow(/illegal characters/) // space too
	})

	it('throws on cookie domain or path with header-breaking characters', () => {
		expect(() => serializeCookie('x', 'y', { domain: 'example.test\r\nSet-Cookie: evil=1' })).toThrow(/cookie domain/)
		expect(() => serializeCookie('x', 'y', { domain: '-bad.example' })).toThrow(/cookie domain/)
		expect(() => serializeCookie('x', 'y', { path: '/ok\r\nSet-Cookie: evil=1' })).toThrow(/cookie path/)
		expect(() => serializeCookie('x', 'y', { path: '/bad;path' })).toThrow(/cookie path/)
	})

	it('accepts the full set of valid cookie-value characters', () => {
		expect(() => serializeCookie('x', '!#$%&()*+-./0123456789')).not.toThrow()
		expect(() => serializeCookie('x', 'abcdef-XYZ_0-9')).not.toThrow()
		expect(() => serializeCookie('x', 'a1b2c3-:<>?@[]^_`{|}~')).not.toThrow()
	})
})
