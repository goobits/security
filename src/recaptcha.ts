/**
 * Server-side Google reCAPTCHA (v2 + v3) token verification.
 *
 * @module @goobits/security/recaptcha
 */

import { isProduction, readEnv } from './_internal/env.js'
import { type Logger, resolveLogger } from './logger.js'

const RECAPTCHA_VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify'

export interface RecaptchaOptions {
	/**
	 * reCAPTCHA secret key. If omitted, falls back to `RECAPTCHA_SECRET_KEY`
	 * env var. If both are missing, verification fails (unless `allowInDevelopment`
	 * is explicitly enabled).
	 */
	secretKey?: string
	/** Expected action name (v3 only). If set, response action must match. */
	action?: string
	/** Minimum score threshold (v3, 0.0-1.0). Default: 0.5. */
	minScore?: number
	/**
	 * Dev escape hatch: when `true` AND `NODE_ENV !== 'production'` AND the
	 * secret key is missing, verification passes. **Default: `false`** — you
	 * must explicitly opt in. This default ensures that runtimes where
	 * `NODE_ENV` is unset (Cloudflare Workers, Deno, many CI environments)
	 * do NOT silently disable CAPTCHA.
	 *
	 * In production this flag is always ignored — missing secret always fails.
	 */
	allowInDevelopment?: boolean
	/** Network timeout in milliseconds. Default: 5000. */
	timeoutMs?: number
	/** Pluggable logger. Default: silent. */
	logger?: Logger
}

interface RecaptchaApiResponse {
	success: boolean
	score?: number
	action?: string
	hostname?: string
	challenge_ts?: string
	'error-codes'?: string[]
}

export type RecaptchaResult =
	| {
		success: true
		score?: number
		action?: string
		raw: RecaptchaApiResponse
	}
	| {
		success: false
		reason: 'missing-token' | 'missing-secret' | 'api-error' | 'verification-failed' | 'score-too-low' | 'action-mismatch'
		errorCodes?: string[]
		statusCode?: number
		score?: number
		action?: string
		raw?: RecaptchaApiResponse
	}

/**
 * Verify a reCAPTCHA token. Returns a discriminated-union result describing
 * exactly why verification succeeded or failed.
 *
 * @example
 * ```ts
 * const result = await verifyRecaptcha(token, {
 *   action: 'submit_contact_form',
 *   minScore: 0.7
 * })
 * if (!result.success) {
 *   return new Response(`reCAPTCHA failed: ${ result.reason }`, { status: 400 })
 * }
 * ```
 */
export async function verifyRecaptcha(
	token: string | null | undefined,
	options: RecaptchaOptions = {}
): Promise<RecaptchaResult> {
	const {
		secretKey = readEnv('RECAPTCHA_SECRET_KEY'),
		action,
		minScore = 0.5,
		allowInDevelopment = false,
		timeoutMs = 5000,
		logger
	} = options

	const log = resolveLogger(logger)

	if (!token) {
		log.warn('reCAPTCHA verification called without a token')
		return { success: false, reason: 'missing-token' }
	}

	if (!secretKey) {
		log.error('RECAPTCHA_SECRET_KEY is not set')
		if (!isProduction() && allowInDevelopment) {
			log.warn('Allowing reCAPTCHA verification to pass (allowInDevelopment=true, NODE_ENV !== production)')
			return { success: true, raw: { success: true } }
		}
		return { success: false, reason: 'missing-secret' }
	}

	const controller = new AbortController()
	const timeout = setTimeout(() => controller.abort(), timeoutMs)

	try {
		const response = await fetch(RECAPTCHA_VERIFY_URL, {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ secret: secretKey, response: token }),
			signal: controller.signal
		})

		if (!response.ok) {
			log.error('reCAPTCHA API returned non-OK status', { statusCode: response.status })
			return { success: false, reason: 'api-error', statusCode: response.status }
		}

		const data = await response.json() as RecaptchaApiResponse

		if (!data.success) {
			log.warn('reCAPTCHA verification failed', { errorCodes: data['error-codes'] })
			const result: RecaptchaResult = {
				success: false,
				reason: 'verification-failed',
				raw: data
			}
			if (data['error-codes']) result.errorCodes = data['error-codes']
			return result
		}

		// v3-specific checks
		if (typeof data.score === 'number') {
			if (data.score < minScore) {
				log.warn('reCAPTCHA score too low', {
					score: data.score,
					minimum: minScore,
					action: data.action
				})
				const result: RecaptchaResult = { success: false, reason: 'score-too-low', score: data.score, raw: data }
				if (data.action !== undefined) result.action = data.action
				return result
			}

			if (action && data.action !== action) {
				log.warn('reCAPTCHA action mismatch', {
					expected: action,
					actual: data.action,
					score: data.score
				})
				const result: RecaptchaResult = { success: false, reason: 'action-mismatch', score: data.score, raw: data }
				if (data.action !== undefined) result.action = data.action
				return result
			}
		}

		const result: RecaptchaResult = { success: true, raw: data }
		if (data.score !== undefined) result.score = data.score
		if (data.action !== undefined) result.action = data.action
		return result
	} catch(error) {
		log.error('reCAPTCHA API request failed', { error: String(error) })
		return { success: false, reason: 'api-error' }
	} finally {
		clearTimeout(timeout)
	}
}

/**
 * Convenience boolean wrapper around `verifyRecaptcha()` for the common case
 * where callers only need to know "valid / not valid".
 */
export async function verifyRecaptchaToken(
	token: string | null | undefined,
	options: RecaptchaOptions = {}
): Promise<boolean> {
	const result = await verifyRecaptcha(token, options)
	return result.success
}
