/**
 * Browser fetch helper for double-submit CSRF tokens.
 *
 * Reads the CSRF token from a cookie and echoes it in the CSRF header for
 * unsafe same-origin requests. Framework-agnostic and browser-only by default,
 * with injectable hooks for tests or custom runtimes.
 *
 * @module @goobits/security/csrf-client
 */

import { CSRF_COOKIE_NAME, CSRF_HEADER_NAME } from './MemoryCsrfStore.js'

const DEFAULT_SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

export interface CsrfFetchConfig {
	cookieName?: string
	headerName?: string
	safeMethods?: Iterable<string>
	fetch?: typeof fetch
	readToken?: (cookieName: string) => string | null
	baseUrl?: string
}

export type CsrfFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>

export function readBrowserCookie(name: string, cookieHeader?: string): string | null {
	const source =
		cookieHeader ??
		(typeof document === 'undefined' ? null : document.cookie)
	if (!source) return null

	const prefix = `${encodeURIComponent(name)}=`
	for (const cookie of source.split(';')) {
		const trimmed = cookie.trim()
		if (trimmed.startsWith(prefix)) {
			return decodeURIComponent(trimmed.slice(prefix.length))
		}
	}
	return null
}

export function isSameOriginRequest(input: RequestInfo | URL, baseUrl?: string): boolean {
	const base =
		baseUrl ??
		(typeof window === 'undefined' ? null : window.location.href)
	if (!base) return false

	const requestUrl = input instanceof Request ? input.url : String(input)
	try {
		return new URL(requestUrl, base).origin === new URL(base).origin
	} catch {
		return false
	}
}

export function createCsrfFetch(config: CsrfFetchConfig = {}): CsrfFetch {
	const cookieName = config.cookieName ?? CSRF_COOKIE_NAME
	const headerName = config.headerName ?? CSRF_HEADER_NAME
	const safeMethods = new Set(
		[...(config.safeMethods ?? DEFAULT_SAFE_METHODS)].map(method => method.toUpperCase())
	)
	const readToken = config.readToken ?? readBrowserCookie

	return function csrfFetch(input: RequestInfo | URL, init: RequestInit = {}) {
		const method = (init.method ?? (input instanceof Request ? input.method : 'GET')).toUpperCase()
		const headers = new Headers(
			init.headers ?? (input instanceof Request ? input.headers : undefined)
		)
		const token = readToken(cookieName)

		if (
			token &&
			isSameOriginRequest(input, config.baseUrl) &&
			!safeMethods.has(method) &&
			!headers.has(headerName)
		) {
			headers.set(headerName, token)
		}

		const fetchImpl = config.fetch ?? globalThis.fetch
		if (!fetchImpl) {
			throw new Error('createCsrfFetch: fetch is not available')
		}
		return fetchImpl(input, { ...init, headers })
	}
}

export const csrfFetch = createCsrfFetch()
