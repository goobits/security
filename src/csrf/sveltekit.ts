/**
 * SvelteKit CSRF helpers.
 *
 * @module @goobits/security/csrf/sveltekit
 */

import type { Cookies, Handle, RequestEvent } from '@sveltejs/kit'

import { resolveLogger } from '../_internal/resolveLogger.js'
import { getRandomBytes } from '../_internal/crypto.js'
import {
	createCsrf,
	type CsrfConfig,
	type CsrfGenerateOptions,
	type CsrfProtection,
	type CsrfValidateOptions
} from '../csrf.js'
import { bytesToBase64Url } from '../crypto/encoding.js'
import { safeErrorContext } from '../logger.js'
import { BodyTooLargeError, readRequestBodyBytes } from '../requestBody.js'
import { isProductionRuntime } from '../runtime.js'

const DEFAULT_MAX_BODY_BYTES = 65_536
const DEFAULT_SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS'] as const

/** Configures CSRF protection for SvelteKit requests and cookies. */
export interface SvelteKitCsrfConfig extends CsrfConfig {
	/**
	 * Resolve the current authenticated-session binding. Returning null uses a
	 * server-issued HttpOnly host cookie for anonymous requests.
	 */
	getSessionBinding?(event: RequestEvent): string | null | undefined | Promise<string | null | undefined>
	/** Form or JSON field containing the submitted token. Default: `csrf_token`. */
	tokenFieldName?: string
	/** Maximum request body bytes inspected for a token. Default: 64 KiB. */
	maxBodyBytes?: number
	/** Methods that do not require a CSRF token. Default: GET, HEAD, OPTIONS. */
	safeMethods?: readonly string[]
	/** Optional request predicate for routes protected by another mechanism. */
	skip?(event: RequestEvent): boolean | Promise<boolean>
	/** Track generated token expiry in the configured store. Default: false. */
	trackExpiry?: boolean
	/** Check store-tracked expiry while validating. Defaults to `trackExpiry`. */
	checkExpiry?: boolean
	/** Customize the rejected response. Default: plain-text HTTP 403. */
	buildFailureResponse?(event: RequestEvent): Response
}

/** Minimal SvelteKit cookie surface needed by the CSRF adapter. */
export type SvelteKitCsrfCookies = Pick<Cookies, 'get' | 'set'>

/** Generation options when a SvelteKit event resolves the binding. */
export type SvelteKitCsrfGenerateOptions = Omit<CsrfGenerateOptions, 'sessionBinding'>

/** CSRF operations bound to SvelteKit's request and cookie APIs. */
export interface SvelteKitCsrf {
	readonly cookieName: string
	readonly bindingCookieName: string
	readonly headerName: string
	readonly protection: CsrfProtection
	/** Generate a token for an explicit binding without requiring a request event. */
	issue(cookies: SvelteKitCsrfCookies, options: CsrfGenerateOptions): Promise<string>
	/** Generate a token bound to the current session or anonymous host cookie. */
	generate(event: RequestEvent, options?: SvelteKitCsrfGenerateOptions): Promise<string>
	/** Return a valid token for the current binding, replacing stale tokens. */
	getOrCreate(event: RequestEvent): Promise<string>
	/** Validate a request against an explicit binding and compatible cookie reader. */
	validateRequest(
		request: Request,
		cookies: Pick<Cookies, 'get'>,
		options: CsrfValidateOptions
	): Promise<boolean>
	/** Validate the request's header or bounded body token against its cookie. */
	validate(event: RequestEvent): Promise<boolean>
	/** SvelteKit handle that enforces validation for unsafe methods. */
	readonly handle: Handle
}

/**
 * Create signed, session-bound double-submit CSRF protection for SvelteKit.
 *
 * Set `trackExpiry: true` only when the configured token store is shared by
 * every service instance. Cookie expiration is the default lifecycle owner. If
 * `getSessionBinding` returns null, anonymous requests are bound to a protected
 * `__Host-` cookie in secure deployments.
 */
export function createSvelteKitCsrf(config: SvelteKitCsrfConfig): SvelteKitCsrf {
	const log = resolveLogger(config.logger)
	const tokenFieldName = config.tokenFieldName ?? 'csrf_token'
	const maxBodyBytes = config.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES
	const safeMethods = new Set(
		(config.safeMethods ?? DEFAULT_SAFE_METHODS).map((method) => method.toUpperCase())
	)
	const trackExpiry = config.trackExpiry ?? false
	const checkExpiry = config.checkExpiry ?? trackExpiry
	const cookieOptions = config.cookieOptions ?? {
		httpOnly: true,
		secure: isProductionRuntime(),
		sameSite: 'lax' as const,
		path: '/',
		maxAge: 60 * 60 * 24
	}
	const protection = createCsrf({ ...config, cookieOptions })
	const secureCookies = cookieOptions.secure === true
	const bareCookieName = protection.cookieName.startsWith('__Host-')
		? protection.cookieName.slice('__Host-'.length)
		: protection.cookieName
	const bindingCookieName = secureCookies
		? `__Host-${bareCookieName}-binding`
		: `${bareCookieName}-binding`
	const bindingCookieOptions = {
		httpOnly: true,
		secure: secureCookies,
		sameSite: 'lax' as const,
		path: '/',
		...(cookieOptions.maxAge === undefined ? {} : { maxAge: cookieOptions.maxAge })
	}

	if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes <= 0) {
		throw new Error('createSvelteKitCsrf: maxBodyBytes must be a positive safe integer')
	}
	if (!tokenFieldName) {
		throw new Error('createSvelteKitCsrf: tokenFieldName must not be empty')
	}

	async function readBodyToken(request: Request): Promise<string | null> {
		const contentType = request.headers.get('content-type')?.toLowerCase() ?? ''
		const isForm =
			contentType.includes('application/x-www-form-urlencoded') ||
			contentType.includes('multipart/form-data')
		const isJson = contentType.includes('application/json')
		if (!isForm && !isJson) return null

		try {
			const bytes = await readRequestBodyBytes(request.clone(), { maxBytes: maxBodyBytes })
			if (bytes === undefined) return null

			if (isJson) {
				const body: unknown = JSON.parse(new TextDecoder().decode(bytes))
				if (!body || typeof body !== 'object' || Array.isArray(body)) return null
				const value = (body as Record<string, unknown>)[tokenFieldName]
				return typeof value === 'string' ? value : null
			}

			if (contentType.includes('application/x-www-form-urlencoded')) {
				return new URLSearchParams(new TextDecoder().decode(bytes)).get(tokenFieldName)
			}

			return (
				(await new Response(bytes, { headers: { 'Content-Type': contentType } }).formData())
					.get(tokenFieldName)
					?.toString() ?? null
			)
		} catch (error) {
			if (error instanceof BodyTooLargeError) {
				log.warn('CSRF request body too large', { maxBodyBytes })
			} else {
				log.debug('CSRF request body could not be parsed', safeErrorContext(error))
			}
			return null
		}
	}

	async function issue(
		cookies: SvelteKitCsrfCookies,
		options: CsrfGenerateOptions
	): Promise<string> {
		const token = await protection.generate({ trackExpiry, ...options })
		cookies.set(protection.cookieName, token, {
			...cookieOptions,
			path: cookieOptions.path ?? '/'
		})
		return token
	}

	function readFallbackBinding(cookies: Pick<Cookies, 'get'>): string | null {
		const value = cookies.get(bindingCookieName)
		return value && /^[A-Za-z0-9_-]{43}$/u.test(value) ? value : null
	}

	async function resolveBinding(event: RequestEvent, createFallback: boolean): Promise<string | null> {
		const sessionBinding = await config.getSessionBinding?.(event)
		if (sessionBinding !== null && sessionBinding !== undefined && sessionBinding !== '') {
			return sessionBinding
		}

		const existing = readFallbackBinding(event.cookies)
		if (existing || !createFallback) return existing

		const binding = bytesToBase64Url(getRandomBytes(32))
		event.cookies.set(bindingCookieName, binding, bindingCookieOptions)
		return binding
	}

	async function generate(
		event: RequestEvent,
		options: SvelteKitCsrfGenerateOptions = {}
	): Promise<string> {
		const sessionBinding = await resolveBinding(event, true)
		return issue(event.cookies, { ...options, sessionBinding: sessionBinding! })
	}

	async function getOrCreate(event: RequestEvent): Promise<string> {
		const sessionBinding = await resolveBinding(event, true)
		const token = event.cookies.get(protection.cookieName)
		if (token && (await validatePair(token, token, { sessionBinding: sessionBinding!, checkExpiry }))) {
			return token
		}
		return issue(event.cookies, { sessionBinding: sessionBinding!, trackExpiry })
	}

	async function validatePair(
		cookieToken: string,
		requestToken: string,
		options: CsrfValidateOptions
	): Promise<boolean> {
		const headers = new Headers({
			cookie: `${protection.cookieName}=${cookieToken}`,
			[protection.headerName]: requestToken
		})
		return protection.validate(new Request('https://csrf.internal/', { headers }), options)
	}

	async function validateRequest(
		request: Request,
		cookies: Pick<Cookies, 'get'>,
		options: CsrfValidateOptions
	): Promise<boolean> {
		const cookieToken = cookies.get(protection.cookieName)
		if (!cookieToken) return false

		const requestToken =
			request.headers.get(protection.headerName) ?? (await readBodyToken(request))
		if (!requestToken) return false

		return validatePair(cookieToken, requestToken, options)
	}

	async function validate(event: RequestEvent): Promise<boolean> {
		const sessionBinding = await resolveBinding(event, false)
		if (!sessionBinding) return false
		return validateRequest(event.request, event.cookies, { sessionBinding, checkExpiry })
	}

	const handle: Handle = async ({ event, resolve }) => {
		if (safeMethods.has(event.request.method.toUpperCase()) || (await config.skip?.(event))) {
			return resolve(event)
		}
		if (!(await validate(event))) {
			return (
				config.buildFailureResponse?.(event) ??
				new Response('Invalid or missing CSRF token', {
					status: 403,
					headers: { 'Content-Type': 'text/plain' }
				})
			)
		}
		return resolve(event)
	}

	return {
		cookieName: protection.cookieName,
		bindingCookieName,
		headerName: protection.headerName,
		protection,
		issue,
		generate,
		getOrCreate,
		validateRequest,
		validate,
		handle
	}
}
