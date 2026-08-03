/**
 * SvelteKit rate-limit helpers.
 *
 * @module @goobits/security/rate-limit/sveltekit
 */

import type { Handle, RequestEvent } from '@sveltejs/kit'

import { resolveLogger } from '../_internal/resolveLogger.js'
import type { Logger } from '../logger.js'
import type { RateLimitResult, RateLimiter } from './index.js'

/** Rate Limit Handle Options request or option shape for rate limiting. */
export interface RateLimitHandleOptions {
	/** Function to derive the rate-limit identifier from a SvelteKit event. */
	identifier(event: RequestEvent): string | Promise<string>
	/** Limiter instance. */
	limiter: RateLimiter
	/** Optional predicate to skip rate limiting for some requests. */
	skip?(event: RequestEvent): boolean | Promise<boolean>
	/** Customize the 429 response body. Default: JSON `{ error, retryAfter }`. */
	buildResponse?(verdict: Extract<RateLimitResult, { allowed: false }>): Response
	/** Pluggable logger. Default: silent. */
	logger?: Logger
}

/**
 * Build a SvelteKit `Handle` middleware that rate-limits every request.
 *
 * @example
 * ```ts
 * // src/hooks.server.ts
 * import { sequence } from '@sveltejs/kit/hooks'
 * import { createRateLimiter } from '@goobits/security/rate-limit'
 * import { createRateLimitHandle } from '@goobits/security/rate-limit/sveltekit'
 *
 * const limiter = createRateLimiter({
 *   windows: [{ name: 'burst', windowMs: 60_000, maxEvents: 30 }]
 * })
 *
 * export const handle = sequence(
 *   createRateLimitHandle({
 *     limiter,
 *     identifier: (event) => event.getClientAddress()
 *   })
 * )
 * ```
 */
export function createRateLimitHandle(options: RateLimitHandleOptions): Handle {
	const log = resolveLogger(options.logger)
	const build = options.buildResponse ?? defaultRateLimitResponse

	return async ({ event, resolve }) => {
		if (options.skip && (await options.skip(event))) {
			return resolve(event)
		}

		const identifier = await options.identifier(event)
		const verdict = await options.limiter.check(identifier)

		if (verdict.allowed === false) {
			log.warn('Rate-limited request', {
				path: event.url.pathname,
				identifier,
				window: verdict.window,
				retryAfterSec: verdict.retryAfterSec
			})
			return build(verdict)
		}

		const response = await resolve(event)
		response.headers.set('X-RateLimit-Remaining', String(verdict.remaining))
		response.headers.set('X-RateLimit-Reset', String(Math.floor(verdict.resetAtMs / 1000)))
		return response
	}
}

function defaultRateLimitResponse(verdict: Extract<RateLimitResult, { allowed: false }>): Response {
	return new Response(
		JSON.stringify({
			error: 'Too many requests',
			retryAfter: verdict.retryAfterSec,
			window: verdict.window
		}),
		{
			status: 429,
			headers: {
				'Content-Type': 'application/json',
				'Retry-After': String(verdict.retryAfterSec)
			}
		}
	)
}
