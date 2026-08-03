/**
 * CSRF protection  -  double-submit cookie pattern with optional expiration.
 *
 * Strategy:
 *   1. Server generates a random 256-bit token and sets it as an HttpOnly cookie.
 *   2. Server also exposes the token via response header so the client can echo
 *      it back in a request header on subsequent POST/PUT/DELETE requests.
 *   3. On those requests, server compares cookie token with header token using
 *      a constant-time comparison.
 *
 * Token store is pluggable: a `Map` for in-memory (default; single-instance) or
 * any object implementing `CsrfTokenStore` (multi-instance, e.g. Redis  -  see
 * `@goobits/security/csrf-redis`).
 *
 * @module @goobits/security/csrf
 */

import { getRandomBytes, timingSafeEqualBytes, toBytes, toHex } from './_internal/crypto.js'
import { type CookieOptions, parseCookies, serializeCookie } from './_internal/cookies.js'
import { isProductionRuntime, readRuntimeEnv } from './runtime.js'
import { resolveLogger } from './_internal/resolveLogger.js'
import { safeErrorContext, type Logger } from './logger.js'

/** Names the CSRF cookie name used by browser and server guards. */
export const CSRF_COOKIE_NAME = 'csrf-token'
/** Names the CSRF header name used by browser and server guards. */
export const CSRF_HEADER_NAME = 'X-CSRF-Token'
/** Names the CSRF token expiry ms used by browser and server guards. */
export const CSRF_TOKEN_EXPIRY_MS = 60 * 60 * 1000 // 1 hour

/**
 * Pluggable CSRF token store. Defaults to an in-memory `Map`. To use Redis
 * (multi-instance), provide an adapter from `@goobits/security/csrf-redis`.
 */
export interface CsrfTokenStore {
	get(token: string): Promise<number | undefined> | number | undefined
	set(token: string, expiresAt: number, ttlMs?: number): Promise<void> | void
	delete(token: string): Promise<void> | void
	clear(): Promise<void> | void
	readonly size?: number
}

/** Describes the CSRF store or request options used by the in-memory guard. */
export interface CsrfConfig {
	/** Cookie name. Default: `'csrf-token'`. */
	cookieName?: string
	/** Request header name carrying the token. Default: `'X-CSRF-Token'`. */
	headerName?: string
	/**
	 * Cookie options. **Completely replaces defaults** when supplied  -  does
	 * NOT merge. The defaults are: `{ httpOnly: true, secure: NODE_ENV === 'production',
	 * sameSite: 'lax', path: '/', maxAge: 86400 }`. If you only want to tweak one
	 * field, copy the defaults first.
	 */
	cookieOptions?: CookieOptions
	/** Token TTL in ms when `trackExpiry` is true. Default: 1 hour. */
	tokenExpiryMs?: number
	/** Backing store. Default: in-memory `Map`. */
	tokenStore?: CsrfTokenStore
	/** Pluggable logger. Default: silent. */
	logger?: Logger
	/**
	 * Disable validation entirely. **For tests only.** Set via `DISABLE_CSRF=true`
	 * env var OR via this option. **Throws at `createCsrf()` time in production**
	 * (`NODE_ENV === 'production'`)  -  fail loud, fail early.
	 */
	disabled?: boolean
	/**
	 * If true (default), errors from the token store (e.g. Redis connection
	 * failure) cause `validate()` to return false. Set to false only when an
	 * explicit availability-over-correctness policy accepts fail-open expiry
	 * checks; the cookie/header constant-time comparison still applies.
	 */
	failClosed?: boolean
}

/** Describes the CSRF store or request options used by the in-memory guard. */
export interface CsrfGenerateOptions {
	/** Override the default TTL. */
	expiryMs?: number
	/** If false, the token is generated but not stored. Default: true. */
	trackExpiry?: boolean
}

/** Describes the CSRF store or request options used by the in-memory guard. */
export interface CsrfValidateOptions {
	/** If true, validation also checks store-tracked expiration. Default: false. */
	checkExpiry?: boolean
}

/** @deprecated Use `CsrfGenerateOptions`. */
export type GenerateOptions = CsrfGenerateOptions

/** @deprecated Use `CsrfValidateOptions`. */
export type ValidateOptions = CsrfValidateOptions

/** Configures the bounded in-memory CSRF token store. */
export interface MemoryCsrfStoreOptions {
	/** Maximum number of tracked tokens. Default: 10,000. */
	maxKeys?: number
}

/** Describes the CSRF store or request options used by the in-memory guard. */
export class MemoryCsrfStore implements CsrfTokenStore {
	private readonly map = new Map<string, number>()
	private readonly maxKeys: number

	constructor(options: MemoryCsrfStoreOptions = {}) {
		const maxKeys = options.maxKeys ?? 10_000
		if (!Number.isSafeInteger(maxKeys) || maxKeys <= 0) {
			throw new Error('MemoryCsrfStore: maxKeys must be a positive safe integer')
		}
		this.maxKeys = maxKeys
	}

	get size(): number {
		return this.map.size
	}

	get(token: string): number | undefined {
		return this.map.get(token)
	}

	set(token: string, expiresAt: number): void {
		if (!this.map.has(token) && this.map.size >= this.maxKeys) {
			this.cleanup()
			while (this.map.size >= this.maxKeys) {
				const oldest = this.map.keys().next()
				if (oldest.done) break
				this.map.delete(oldest.value)
			}
		}
		this.map.set(token, expiresAt)
	}

	delete(token: string): void {
		this.map.delete(token)
	}

	clear(): void {
		this.map.clear()
	}

	cleanup(): number {
		const now = Date.now()
		let count = 0
		for (const [token, expires] of this.map.entries()) {
			if (expires < now) {
				this.map.delete(token)
				count++
			}
		}
		return count
	}
}

function defaultCookieOptions(): CookieOptions {
	return {
		httpOnly: true,
		secure: isProductionRuntime(),
		sameSite: 'lax',
		path: '/',
		maxAge: 60 * 60 * 24
	}
}

/**
 * Create a CSRF protection instance.
 *
 * @example
 * ```ts
 * import { createCsrf } from '@goobits/security/csrf'
 *
 * const csrf = createCsrf({ logger: myLogger })
 *
 * // In a load function / page server hook:
 * const token = csrf.generate()
 * csrf.setCookie(response, token)
 *
 * // In an action / form handler:
 * if (!(await csrf.validate(request))) {
 *   return new Response('Invalid CSRF token', { status: 403 })
 * }
 * ```
 */
export function createCsrf(config: CsrfConfig = {}): CsrfProtection {
	const log = resolveLogger(config.logger)
	const store = config.tokenStore ?? new MemoryCsrfStore()
	const cookieName = config.cookieName ?? CSRF_COOKIE_NAME
	const headerName = config.headerName ?? CSRF_HEADER_NAME
	const cookieOptions = config.cookieOptions ?? defaultCookieOptions()
	const defaultExpiryMs = config.tokenExpiryMs ?? CSRF_TOKEN_EXPIRY_MS

	const envDisabled = readRuntimeEnv('DISABLE_CSRF') === 'true'
	const disabled = config.disabled === true || envDisabled
	const failClosed = config.failClosed !== false

	if (disabled && isProductionRuntime()) {
		throw new Error(
			'@goobits/security/csrf: DISABLE_CSRF is set in production. ' +
				'This config is for tests only. Unset DISABLE_CSRF and remove ' +
				'`disabled: true` from createCsrf() config before deploying.'
		)
	}

	async function generate(options: CsrfGenerateOptions = {}): Promise<string> {
		const { expiryMs = defaultExpiryMs, trackExpiry = true } = options
		const token = toHex(getRandomBytes(32))

		if (trackExpiry) {
			const expires = Date.now() + expiryMs
			await store.set(token, expires, expiryMs)

			// Best-effort opportunistic cleanup for in-memory store.
			if (store instanceof MemoryCsrfStore && Math.random() < 0.1) {
				const cleaned = store.cleanup()
				if (cleaned > 0) log.debug(`Cleaned up ${cleaned} expired CSRF tokens`)
			}
		}

		return token
	}

	function setCookie(response: Response, token: string): void {
		if (!response || !response.headers) {
			log.error('setCookie called with invalid response')
			return
		}
		response.headers.append('Set-Cookie', serializeCookie(cookieName, token, cookieOptions))
		response.headers.set(headerName, token)
	}

	function getToken(request: Request): string | null {
		const cookies = parseCookies(request.headers.get('cookie'))
		return cookies[cookieName] ?? null
	}

	async function isTokenExpired(token: string): Promise<boolean> {
		let expires: number | undefined
		try {
			expires = await store.get(token)
		} catch (err) {
			log.error('Error checking CSRF token expiration', safeErrorContext(err))
			// failClosed=true treats store errors as expired (fail-safe);
			// failClosed=false treats them as not-expired (fail-open for availability).
			return failClosed
		}

		if (expires === undefined) return true

		const expired = Date.now() > expires
		if (expired) {
			try {
				await store.delete(token)
			} catch (err) {
				log.error('Error deleting expired CSRF token', safeErrorContext(err))
			}
			log.warn('CSRF token expired')
		}
		return expired
	}

	async function validate(request: Request, options: CsrfValidateOptions = {}): Promise<boolean> {
		if (disabled && !isProductionRuntime()) {
			log.warn('CSRF validation disabled (test/dev mode)')
			return true
		}

		const cookieToken = getToken(request)
		if (!cookieToken) return false

		const headerToken = request.headers.get(headerName)
		if (!headerToken) return false

		if (options.checkExpiry && (await isTokenExpired(cookieToken))) {
			return false
		}

		return timingSafeEqualBytes(toBytes(cookieToken), toBytes(headerToken))
	}

	async function cleanup(): Promise<number> {
		if (store instanceof MemoryCsrfStore) {
			const count = store.cleanup()
			if (count > 0) log.info(`Cleaned up ${count} expired CSRF tokens`)
			return count
		}
		log.debug('Cleanup not needed for non-memory store (TTL handles expiration)')
		return 0
	}

	async function clear(): Promise<void> {
		await store.clear()
		log.info('Cleared all CSRF tokens from store')
	}

	return {
		cookieName,
		headerName,
		generate,
		setCookie,
		getToken,
		validate,
		cleanup,
		clear,
		get storeSize() {
			return store.size
		}
	}
}

/** Describes the CSRF store or request options used by the in-memory guard. */
export interface CsrfProtection {
	readonly cookieName: string
	readonly headerName: string
	readonly storeSize: number | undefined
	generate(options?: CsrfGenerateOptions): Promise<string>
	setCookie(response: Response, token: string): void
	getToken(request: Request): string | null
	validate(request: Request, options?: CsrfValidateOptions): Promise<boolean>
	cleanup(): Promise<number>
	clear(): Promise<void>
}
