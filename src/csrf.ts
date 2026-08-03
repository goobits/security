/**
 * Session-bound, signed double-submit CSRF protection with optional expiration.
 *
 * Strategy:
 *   1. Server generates a random nonce and signs it together with an opaque
 *      session binding using HMAC-SHA-256.
 *   2. Server sets the signed token as a cookie and exposes it to trusted page
 *      code so the client can echo it in a request header or form field.
 *   3. On unsafe requests, server compares the cookie and submitted token in
 *      constant time, then verifies the signature against the current binding.
 *
 * Token store is pluggable: a `Map` for in-memory (default; single-instance) or
 * any object implementing `CsrfTokenStore` (multi-instance, e.g. Redis  -  see
 * `@goobits/security/csrf-redis`).
 *
 * @module @goobits/security/csrf
 */

import { getRandomBytes, timingSafeEqualBytes, toBytes } from './_internal/crypto.js'
import { type CookieOptions, parseCookies, serializeCookie } from './_internal/cookies.js'
import { isProductionRuntime, readRuntimeEnv } from './runtime.js'
import { resolveLogger } from './_internal/resolveLogger.js'
import { safeErrorContext, type Logger } from './logger.js'
import { bytesToBase64Url } from './crypto/encoding.js'
import { signHmac, verifyHmac } from './crypto/signatures.js'

/** Names the CSRF cookie name used by browser and server guards. */
export const CSRF_COOKIE_NAME = 'csrf-token'
/** Names the CSRF header name used by browser and server guards. */
export const CSRF_HEADER_NAME = 'X-CSRF-Token'
/** Names the CSRF token expiry ms used by browser and server guards. */
export const CSRF_TOKEN_EXPIRY_MS = 60 * 60 * 1000 // 1 hour

const CSRF_TOKEN_CONTEXT = '@goobits/security/csrf/v1'
const CSRF_TOKEN_PATTERN = /^v1\.([A-Za-z0-9_-]{43})\.([A-Za-z0-9_-]{43})$/u
const MIN_SECRET_BYTES = 32
const MAX_SESSION_BINDING_BYTES = 1_024

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
	/**
	 * HMAC secret used to authenticate tokens. Must contain at least 32 UTF-8
	 * bytes and must be identical across every instance serving the application.
	 */
	secret: string | Uint8Array
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
	/**
	 * Opaque authenticated-session identifier or server-issued anonymous binding.
	 * Tokens cannot be replayed under another binding.
	 */
	sessionBinding: string
	/** Override the default TTL. */
	expiryMs?: number
	/** If false, the token is generated but not stored. Default: true. */
	trackExpiry?: boolean
}

/** Describes the CSRF store or request options used by the in-memory guard. */
export interface CsrfValidateOptions {
	/** Current binding that the submitted token must authenticate. */
	sessionBinding: string
	/** If true, validation also checks store-tracked expiration. Default: false. */
	checkExpiry?: boolean
}

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

function validateSecret(secret: string | Uint8Array): Uint8Array {
	const bytes = typeof secret === 'string' ? toBytes(secret) : secret
	if (!(bytes instanceof Uint8Array) || bytes.byteLength < MIN_SECRET_BYTES) {
		throw new Error(
			`@goobits/security/csrf: secret must contain at least ${MIN_SECRET_BYTES} bytes`
		)
	}
	return Uint8Array.from(bytes)
}

function validateSessionBinding(sessionBinding: string): string {
	if (typeof sessionBinding !== 'string' || sessionBinding.length === 0) {
		throw new Error('@goobits/security/csrf: sessionBinding must be a non-empty string')
	}
	if (toBytes(sessionBinding).byteLength > MAX_SESSION_BINDING_BYTES) {
		throw new Error(
			`@goobits/security/csrf: sessionBinding must not exceed ${MAX_SESSION_BINDING_BYTES} bytes`
		)
	}
	return sessionBinding
}

function tokenPayload(sessionBinding: string, nonce: string): string {
	const binding = validateSessionBinding(sessionBinding)
	return `${CSRF_TOKEN_CONTEXT}\0${toBytes(binding).byteLength}\0${binding}\0${nonce}`
}

/**
 * Create a CSRF protection instance.
 *
 * @example
 * ```ts
 * import { createCsrf } from '@goobits/security/csrf'
 *
 * const csrf = createCsrf({ secret: process.env.CSRF_SECRET! })
 *
 * // In a load function / page server hook:
 * const token = await csrf.generate({ sessionBinding: session.id })
 * csrf.setCookie(response, token)
 *
 * // In an action / form handler:
 * if (!(await csrf.validate(request, { sessionBinding: session.id }))) {
 *   return new Response('Invalid CSRF token', { status: 403 })
 * }
 * ```
 */
export function createCsrf(config: CsrfConfig): CsrfProtection {
	const log = resolveLogger(config.logger)
	const secret = validateSecret(config.secret)
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

	async function generate(options: CsrfGenerateOptions): Promise<string> {
		const { expiryMs = defaultExpiryMs, trackExpiry = true } = options
		const nonce = bytesToBase64Url(getRandomBytes(32))
		const signature = await signHmac(tokenPayload(options.sessionBinding, nonce), secret)
		const token = `v1.${nonce}.${signature.value}`

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

	async function validate(request: Request, options: CsrfValidateOptions): Promise<boolean> {
		if (disabled && !isProductionRuntime()) {
			log.warn('CSRF validation disabled (test/dev mode)')
			return true
		}

		const cookieToken = getToken(request)
		if (!cookieToken) return false

		const headerToken = request.headers.get(headerName)
		if (!headerToken) return false
		if (!timingSafeEqualBytes(toBytes(cookieToken), toBytes(headerToken))) return false

		const match = CSRF_TOKEN_PATTERN.exec(cookieToken)
		if (!match) return false
		const [, nonce, signature] = match
		if (
			!(await verifyHmac(
				tokenPayload(options.sessionBinding, nonce!),
				{ algorithm: 'HS256', value: signature! },
				secret
			))
		) {
			return false
		}

		if (options.checkExpiry && (await isTokenExpired(cookieToken))) {
			return false
		}

		return true
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
	generate(options: CsrfGenerateOptions): Promise<string>
	setCookie(response: Response, token: string): void
	getToken(request: Request): string | null
	validate(request: Request, options: CsrfValidateOptions): Promise<boolean>
	cleanup(): Promise<number>
	clear(): Promise<void>
}
