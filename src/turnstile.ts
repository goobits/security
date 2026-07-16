/**
 * Server-side Cloudflare Turnstile token verification.
 *
 * Sister module to `./recaptcha.js`. Same shape, Cloudflare-specific.
 *
 * @module @goobits/security/turnstile
 */

import { isProduction, readEnv } from './_internal/env.js'
import { resolveLogger } from './_internal/resolveLogger.js'
import type { Logger } from './logger.js'
import { safeErrorContext } from './logger.js'

const TURNSTILE_VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'

const DEFAULT_LOOPBACK_HOSTS = ['127.0.0.1', '::1', 'localhost', '0.0.0.0']

/** Options for `verifyTurnstile()`. */
export interface TurnstileOptions {
	/**
	 * Turnstile secret key. If omitted, falls back to `TURNSTILE_SECRET_KEY`
	 * env var. If both are missing, verification fails unless
	 * `allowInDevelopment` is explicitly enabled AND `NODE_ENV !== 'production'`.
	 */
	secretKey?: string

	/** Expected action name. If set, response action must match. */
	action?: string

	/** Expected hostname. If set, response hostname must match. */
	hostname?: string

	/**
	 * Client IP, forwarded to Cloudflare as `remoteip`. Also used by
	 * `bypassLocalhost` to decide whether to short-circuit.
	 */
	remoteIp?: string

	/**
	 * Skip the siteverify call entirely when `remoteIp` matches a loopback
	 * address. Convenience for local dev (browsing to localhost while CF
	 * widgets can't resolve a real remote IP). Default: `false`.
	 *
	 * In production this flag is ALWAYS ignored  -  loopback bypass is never
	 * applied when `NODE_ENV === 'production'`.
	 */
	bypassLocalhost?: boolean

	/**
	 * Custom loopback host list. Defaults to
	 * `['127.0.0.1', '::1', 'localhost', '0.0.0.0']`.
	 */
	bypassHosts?: string[]

	/**
	 * Dev escape hatch: when `true` AND `NODE_ENV !== 'production'` AND the
	 * secret key is missing, verification passes. Default: `false`.
	 *
	 * In production this flag is always ignored  -  missing secret always fails.
	 */
	allowInDevelopment?: boolean

	/** Network timeout in milliseconds. Default: 5000. */
	timeoutMs?: number

	/** Pluggable logger. Default: silent. */
	logger?: Logger
}

/** Raw response shape from Cloudflare's siteverify API. */
export interface TurnstileApiResponse {
	success: boolean
	action?: string
	hostname?: string
	challenge_ts?: string
	cdata?: string
	metadata?: { interactive?: boolean }
	'error-codes'?: string[]
}

/** Discriminated-union result type returned by `verifyTurnstile()`. */
export type TurnstileResult =
	| {
			success: true
			action?: string
			hostname?: string
			raw: TurnstileApiResponse
	  }
	| {
			success: false
			reason:
				| 'missing-token'
				| 'missing-secret'
				| 'api-error'
				| 'verification-failed'
				| 'action-mismatch'
				| 'hostname-mismatch'
			errorCodes?: string[]
			statusCode?: number
			raw?: TurnstileApiResponse
	  }

/**
 * Verify a Turnstile token against Cloudflare's siteverify endpoint.
 *
 * Never throws  -  all failures are reported via the discriminated `result.success`
 * field plus a closed-enum `reason`.
 *
 * @example
 *   const result = await verifyTurnstile(token, { secretKey, remoteIp })
 *   if (!result.success) error(403, `Turnstile failed: ${result.reason}`)
 */
export async function verifyTurnstile(
	token: string | null | undefined,
	options: TurnstileOptions = {}
): Promise<TurnstileResult> {
	const {
		secretKey = readEnv('TURNSTILE_SECRET_KEY'),
		action,
		hostname,
		remoteIp,
		bypassLocalhost = false,
		bypassHosts = DEFAULT_LOOPBACK_HOSTS,
		allowInDevelopment = false,
		timeoutMs = 5000,
		logger
	} = options

	const log = resolveLogger(logger)

	if (!token) {
		log.warn('Turnstile verification called without a token')
		return { success: false, reason: 'missing-token' }
	}

	// Loopback bypass  -  only outside production, only when explicitly opted in.
	if (bypassLocalhost && !isProduction() && remoteIp && bypassHosts.includes(remoteIp)) {
		log.info('Turnstile bypassed for loopback remoteIp', { remoteIp })
		return {
			success: true,
			...(hostname !== undefined ? { hostname } : {}),
			raw: {
				success: true,
				...(hostname !== undefined ? { hostname } : {})
			}
		}
	}

	if (!secretKey) {
		log.error('TURNSTILE_SECRET_KEY is not set')
		if (!isProduction() && allowInDevelopment) {
			log.warn(
				'Allowing Turnstile verification to pass (allowInDevelopment=true, NODE_ENV !== production)'
			)
			return { success: true, raw: { success: true } }
		}
		return { success: false, reason: 'missing-secret' }
	}

	const controller = new AbortController()
	const timeout = setTimeout(() => controller.abort(), timeoutMs)

	try {
		const body = new URLSearchParams({ secret: secretKey, response: token })
		if (remoteIp) body.set('remoteip', remoteIp)

		const response = await fetch(TURNSTILE_VERIFY_URL, {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body,
			signal: controller.signal
		})

		if (!response.ok) {
			log.error('Turnstile API returned non-OK status', { statusCode: response.status })
			return { success: false, reason: 'api-error', statusCode: response.status }
		}

		const data = (await response.json()) as TurnstileApiResponse

		if (!data.success) {
			log.warn('Turnstile verification failed', { errorCodes: data['error-codes'] })
			const result: TurnstileResult = {
				success: false,
				reason: 'verification-failed',
				raw: data
			}
			if (data['error-codes']) result.errorCodes = data['error-codes']
			return result
		}

		if (action && data.action !== action) {
			log.warn('Turnstile action mismatch', { expected: action, actual: data.action })
			return {
				success: false,
				reason: 'action-mismatch',
				raw: data
			}
		}

		if (hostname && data.hostname !== hostname) {
			log.warn('Turnstile hostname mismatch', { expected: hostname, actual: data.hostname })
			return {
				success: false,
				reason: 'hostname-mismatch',
				raw: data
			}
		}

		const result: TurnstileResult = { success: true, raw: data }
		if (data.action !== undefined) result.action = data.action
		if (data.hostname !== undefined) result.hostname = data.hostname
		return result
	} catch (error) {
		log.error('Turnstile API request failed', safeErrorContext(error))
		return { success: false, reason: 'api-error' }
	} finally {
		clearTimeout(timeout)
	}
}
