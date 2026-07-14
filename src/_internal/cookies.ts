/**
 * Cookie parsing + serialization helpers.
 *
 * @internal
 */

type CookieMap = Record<string, string>

export function parseCookies(cookieHeader: string | null | undefined): CookieMap {
	// Use a null-prototype object so attacker-controlled cookie names like
	// `__proto__` or `constructor` don't shift prototype-chain lookups downstream.
	const cookies: CookieMap = Object.create(null) as CookieMap
	if (!cookieHeader) return cookies

	for (const pair of cookieHeader.split(';')) {
		const equalIndex = pair.indexOf('=')
		if (equalIndex > 0) {
			const key = pair.substring(0, equalIndex).trim()
			let value = pair.substring(equalIndex + 1).trim()
			// Strip surrounding double-quotes per RFC 6265 (proxies sometimes emit
			// `name="value"`); preserves the inner value.
			if (
				value.length >= 2 &&
				value.charCodeAt(0) === 0x22 &&
				value.charCodeAt(value.length - 1) === 0x22
			) {
				value = value.slice(1, -1)
			}
			cookies[key] = value
		}
	}

	return cookies
}

export interface CookieOptions {
	httpOnly?: boolean
	secure?: boolean
	sameSite?: 'strict' | 'lax' | 'none'
	path?: string
	domain?: string
	maxAge?: number
	expires?: Date
}

// Cookie name token per RFC 6265: visible ASCII chars except control + separators.
const COOKIE_NAME_RE = /^[!#$%&'*+\-.0-9A-Z^_`a-z|~]+$/
// Cookie value: visible ASCII except CTL (\x00-\x1F, \x7F), space (\x20),
// double-quote (\x22), comma (\x2C), semicolon (\x3B), backslash (\x5C).
const COOKIE_VALUE_RE = /^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*$/
const COOKIE_DOMAIN_RE =
	/^\.?(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$/
const COOKIE_PATH_RE = /^[\x20-\x3A\x3C-\x7E]*$/

export function serializeCookie(name: string, value: string, options: CookieOptions = {}): string {
	if (!COOKIE_NAME_RE.test(name)) {
		throw new Error(`@goobits/security: invalid cookie name "${name}"`)
	}
	if (!COOKIE_VALUE_RE.test(value)) {
		throw new Error(
			'@goobits/security: cookie value contains illegal characters (control / CRLF / quote / comma / semicolon / backslash)'
		)
	}
	if (options.domain && !COOKIE_DOMAIN_RE.test(options.domain)) {
		throw new Error('@goobits/security: cookie domain contains illegal characters')
	}
	if (options.path && !COOKIE_PATH_RE.test(options.path)) {
		throw new Error('@goobits/security: cookie path contains illegal characters')
	}

	const parts: string[] = [`${name}=${value}`]

	if (options.maxAge !== undefined) parts.push(`Max-Age=${options.maxAge}`)
	if (options.expires) parts.push(`Expires=${options.expires.toUTCString()}`)
	if (options.domain) parts.push(`Domain=${options.domain}`)
	if (options.path) parts.push(`Path=${options.path}`)
	if (options.sameSite) {
		const sameSiteValue =
			options.sameSite === 'lax' ? 'Lax' : options.sameSite === 'strict' ? 'Strict' : 'None'
		parts.push(`SameSite=${sameSiteValue}`)
	}
	if (options.httpOnly) parts.push('HttpOnly')
	if (options.secure) parts.push('Secure')

	return parts.join('; ')
}
