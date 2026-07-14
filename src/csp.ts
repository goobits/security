/**
 * Content Security Policy header builder.
 *
 * Provides a generic, parameterized way to construct CSP directives + the
 * eventual `Content-Security-Policy` header value. Consumers pass their
 * vendor allowlist (Stripe, MapLibre, etc.) as `extraSources`; the package
 * has no hardcoded third-party knowledge.
 *
 * @module @goobits/security/csp
 */

import { getRandomBytes } from './_internal/crypto.js'
import { isProduction } from './_internal/env.js'
import { type Logger, resolveLogger } from './logger.js'

/** Standard CSP fetch + navigation directives, plus CSP3 + Trusted Types. */
export type CspDirective =
	| 'default-src'
	| 'script-src'
	// CSP3: fine-grained variants for inline event handlers + non-element scripts.
	| 'script-src-attr'
	| 'script-src-elem'
	| 'style-src'
	// CSP3: fine-grained variants for inline style attributes + <style>/<link>.
	| 'style-src-attr'
	| 'style-src-elem'
	| 'img-src'
	| 'font-src'
	| 'connect-src'
	| 'frame-src'
	| 'frame-ancestors'
	| 'media-src'
	| 'object-src'
	| 'worker-src'
	| 'manifest-src'
	| 'child-src'
	| 'prefetch-src'
	| 'base-uri'
	| 'form-action'
	| 'sandbox'
	| 'report-uri'
	| 'report-to'
	| 'upgrade-insecure-requests'
	| 'block-all-mixed-content'
	// Trusted Types API (Chrome/Edge). Mitigates DOM-XSS by requiring all sinks
	// to consume typed objects produced by named policies.
	| 'trusted-types'
	| 'require-trusted-types-for'

/** Csp Directives typed model for security middleware. */
export type CspDirectives = Partial<Record<CspDirective, string[]>>

/** Csp Config request or option shape for security middleware. */
export interface CspConfig {
	/**
	 * Mode controls baseline permissiveness.
	 *
	 *  - `production` (default): strict, no unsafe-inline/unsafe-eval; HTTPS only for connect-src; etc.
	 *  - `development`: relaxes script/style to allow Vite HMR (`'unsafe-inline'`, `'unsafe-eval'`,
	 *     blob:, `ws://localhost:*`).
	 */
	mode?: 'production' | 'development'

	/**
	 * Per-directive lists merged into the baseline. Use this to add your
	 * vendor allowlist (Stripe, fonts.googleapis.com, your CDN, etc.).
	 *
	 * @example
	 * ```ts
	 * extraSources: {
	 *   'script-src': ['https://js.stripe.com'],
	 *   'img-src':    ['https://*.cdn.example.com', 'https://placehold.co'],
	 *   'connect-src': ['https://api.stripe.com']
	 * }
	 * ```
	 */
	extraSources?: CspDirectives

	/** Per-request nonce (preferred over `'unsafe-inline'`). */
	nonce?: string

	/** Optional `report-uri` for CSP violation reports. */
	reportUri?: string

	/** Optional `report-to` group name (newer browsers). */
	reportTo?: string

	/**
	 * If true, drops the default `frame-ancestors 'none'` (e.g. for embeddable
	 * widgets). Default: false (recommended).
	 */
	allowFraming?: boolean
	/**
	 * Optional logger. Used to warn when `mode: 'development'` is requested
	 * while `NODE_ENV === 'production'` (a setup bug that silently relaxes
	 * CSP to allow `unsafe-inline` / `unsafe-eval`). Default: silent.
	 */
	logger?: Logger
}

const PRODUCTION_BASE: CspDirectives = {
	'default-src': ["'self'"],
	'script-src': ["'self'"],
	'style-src': ["'self'"],
	'img-src': ["'self'", 'data:'],
	'font-src': ["'self'"],
	'connect-src': ["'self'"],
	'frame-ancestors': ["'none'"],
	'object-src': ["'none'"],
	'base-uri': ["'self'"],
	'form-action': ["'self'"],
	'upgrade-insecure-requests': []
}

const DEVELOPMENT_BASE: CspDirectives = {
	'default-src': ["'self'"],
	// HMR needs unsafe-inline + unsafe-eval; blob: for module workers.
	'script-src': ["'self'", "'unsafe-inline'", "'unsafe-eval'", 'blob:'],
	'style-src': ["'self'", "'unsafe-inline'"],
	'img-src': ["'self'", 'data:', 'blob:'],
	'font-src': ["'self'"],
	'connect-src': ["'self'", 'ws:', 'wss:', 'http://localhost:*', 'http://0.0.0.0:*'],
	'frame-ancestors': ["'none'"],
	'object-src': ["'none'"],
	'base-uri': ["'self'"],
	'form-action': ["'self'"],
	'worker-src': ["'self'", 'blob:']
}

function dedupe(values: string[]): string[] {
	const seen = new Set<string>()
	const out: string[] = []
	for (const v of values) {
		if (!seen.has(v)) {
			seen.add(v)
			out.push(v)
		}
	}
	return out
}

function mergeDirectives(base: CspDirectives, extra: CspDirectives): CspDirectives {
	const result: CspDirectives = {}
	const keys = new Set<CspDirective>([
		...(Object.keys(base) as CspDirective[]),
		...(Object.keys(extra) as CspDirective[])
	])
	for (const key of keys) {
		const merged = [...(base[key] ?? []), ...(extra[key] ?? [])]
		result[key] = dedupe(merged)
	}
	return result
}

/**
 * Build the CSP directive map. Returns a plain object: pass it to
 * `buildCspHeader()` for the header value, or inspect/mutate before that.
 */
export function createCspDirectives(config: CspConfig = {}): CspDirectives {
	const {
		mode = 'production',
		extraSources = {},
		nonce,
		reportUri,
		reportTo,
		allowFraming = false,
		logger
	} = config

	const log = resolveLogger(logger)
	if (mode === 'development' && isProduction()) {
		log.warn(
			"CSP mode='development' requested while NODE_ENV=production. " +
				"this relaxes script-src/style-src to allow 'unsafe-inline' and 'unsafe-eval'. " +
				"If unintentional, pass mode='production' or omit the mode option."
		)
	}

	const base = mode === 'development' ? DEVELOPMENT_BASE : PRODUCTION_BASE
	let directives = mergeDirectives(base, extraSources)

	if (nonce) {
		const nonceValue = `'nonce-${nonce}'`
		directives = {
			...directives,
			'script-src': dedupe([...(directives['script-src'] ?? []), nonceValue]),
			'style-src': dedupe([...(directives['style-src'] ?? []), nonceValue])
		}
	}

	if (allowFraming) {
		const { 'frame-ancestors': _frameAncestors, ...rest } = directives
		directives = rest
	}

	if (reportUri) directives = { ...directives, 'report-uri': [reportUri] }
	if (reportTo) directives = { ...directives, 'report-to': [reportTo] }

	return directives
}

/**
 * Serialize a directive map into a `Content-Security-Policy` header value.
 */
export function buildCspHeader(directives: CspDirectives): string {
	const parts: string[] = []
	for (const [name, values] of Object.entries(directives) as Array<[CspDirective, string[]]>) {
		if (values.length === 0) {
			parts.push(name)
		} else {
			parts.push(`${name} ${values.join(' ')}`)
		}
	}
	return parts.join('; ')
}

/**
 * One-shot helper: build directives + serialize them in a single call.
 *
 * @example
 * ```ts
 * const isProd = process.env.NODE_ENV === 'production'
 * // In SvelteKit/Vite, use `import.meta.env.PROD` instead.
 *
 * response.headers.set('Content-Security-Policy', buildCsp({
 *   mode: isProd ? 'production' : 'development',
 *   nonce: locals.cspNonce,
 *   extraSources: {
 *     'script-src': ['https://js.stripe.com'],
 *     'connect-src': ['https://api.stripe.com']
 *   }
 * }))
 * ```
 */
export function buildCsp(config: CspConfig = {}): string {
	return buildCspHeader(createCspDirectives(config))
}

/**
 * Generate a fresh CSP nonce. Use this once per request and inject the same
 * value into both the CSP header and any inline `<script nonce="...">` tags.
 *
 * Returns a URL-safe base64 string (RFC 4648 §5, no padding) of 128 bits
 * entropy, meeting the W3C CSP3 recommendation for nonce randomness.
 */
export function createCspNonce(): string {
	const bytes = getRandomBytes(16)
	let str = ''
	for (let i = 0; i < bytes.length; i++) {
		str += String.fromCharCode(bytes[i] ?? 0)
	}
	return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
