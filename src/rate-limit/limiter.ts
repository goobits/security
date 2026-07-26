import { resolveLogger } from '../_internal/resolveLogger.js'
import { MemoryRateLimitStore } from './memoryStore.js'
import type { RateLimitConfig, RateLimiter, RateLimitResult } from './types.js'

/**
 * Build a rate limiter from a window config.
 *
 * The limiter enforces a sliding window: each call to `check()` records the
 * current timestamp and then verifies that every configured window has at
 * most `maxEvents` timestamps within the trailing `windowMs`.
 *
 * @example
 * ```ts
 * const limiter = createRateLimiter({
 *   windows: [
 *     { name: 'burst', windowMs:  60_000, maxEvents:   5 },
 *     { name: 'hour',  windowMs: 3_600_000, maxEvents:  60 }
 *   ]
 * })
 *
 * const verdict = await limiter.check(clientIp)
 * if (!verdict.allowed) {
 *   return new Response('Too Many Requests', {
 *     status: 429,
 *     headers: { 'Retry-After': String(verdict.retryAfterSec) }
 *   })
 * }
 * ```
 */
export function createRateLimiter(config: RateLimitConfig): RateLimiter {
	if (config.windows.length === 0) {
		throw new Error('createRateLimiter: at least one window required')
	}
	for (const [index, window] of config.windows.entries()) {
		if (typeof window.name !== 'string' || !window.name.trim()) {
			throw new Error(`createRateLimiter: windows[${index}].name must not be empty`)
		}
		if (!Number.isSafeInteger(window.windowMs) || window.windowMs <= 0) {
			throw new Error(
				`createRateLimiter: windows[${index}].windowMs must be a positive safe integer`
			)
		}
		if (!Number.isSafeInteger(window.maxEvents) || window.maxEvents <= 0) {
			throw new Error(
				`createRateLimiter: windows[${index}].maxEvents must be a positive safe integer`
			)
		}
	}

	const log = resolveLogger(config.logger)
	const store = config.store ?? new MemoryRateLimitStore()
	const keyPrefix = config.keyPrefix ?? 'rate-limit'

	// Use the longest window as the storage TTL  -  covers all shorter windows.
	const maxWindowMs = Math.max(...config.windows.map((w) => w.windowMs))
	const maxStoredEvents = Math.max(...config.windows.map((w) => w.maxEvents + 1))

	function buildKey(identifier: string): string {
		return `${keyPrefix}:${identifier}`
	}

	/**
	 * Evaluate the rate-limit verdict for an entry. Pure compute over the
	 * timestamps list  -  no store access. Used by both `check()` (which
	 * increments first) and `peek()` (which reads only).
	 *
	 * When `logOnHit` is true, emits a warning on limit-exceeded  -  `check()`
	 * sets this; `peek()` does not (peeks happen during response-header
	 * builds where a warning per request would be noisy).
	 */
	function evaluateWindows(
		identifier: string,
		timestamps: number[],
		now: number,
		logOnHit: boolean
	): RateLimitResult {
		let tightestRemaining = Number.POSITIVE_INFINITY
		let tightestResetAt = 0
		let tightestWindowName: string | null = null

		for (const window of config.windows) {
			const cutoff = now - window.windowMs
			const inWindow = timestamps.filter((t) => t > cutoff).slice(-(window.maxEvents + 1))
			const remaining = window.maxEvents - inWindow.length

			if (inWindow.length > window.maxEvents) {
				// Limit exceeded for this window. retryAfter = when the oldest in-window
				// timestamp will roll out.
				const oldest = inWindow[0] ?? now
				const resetAt = oldest + window.windowMs
				if (logOnHit) {
					log.warn(`Rate limit hit (window=${window.name})`, {
						identifier,
						events: inWindow.length,
						maxEvents: window.maxEvents
					})
				}
				return {
					allowed: false,
					retryAfterSec: Math.max(1, Math.ceil((resetAt - now) / 1000)),
					resetAtMs: resetAt,
					window: window.name
				}
			}

			if (remaining < tightestRemaining) {
				tightestRemaining = remaining
				const oldest = inWindow[0] ?? now
				tightestResetAt = oldest + window.windowMs
				tightestWindowName = window.name
			}
		}

		const result: Extract<RateLimitResult, { allowed: true }> = {
			allowed: true,
			remaining: Math.max(0, tightestRemaining),
			resetAtMs: tightestResetAt
		}
		if (tightestWindowName) result.window = tightestWindowName
		return result
	}

	async function check(identifier: string): Promise<RateLimitResult> {
		const key = buildKey(identifier)
		const now = Date.now()
		const entry = await store.incrementEntry(key, now, maxWindowMs, maxStoredEvents)
		return evaluateWindows(identifier, entry.timestamps, now, true)
	}

	async function peek(identifier: string): Promise<RateLimitResult> {
		const key = buildKey(identifier)
		const now = Date.now()
		const entry = await store.getEntry(key)
		return evaluateWindows(identifier, entry?.timestamps ?? [], now, false)
	}

	async function reset(identifier: string): Promise<void> {
		await store.deleteEntry(buildKey(identifier))
	}

	return { check, peek, reset, config }
}
