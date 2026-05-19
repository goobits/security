/**
 * Rate limiting — sliding-window counter with pluggable store.
 *
 * @module @goobits/security/rate-limit
 */

import { type Logger, resolveLogger } from '../logger.js'

/** A single window-counter entry. */
export interface RateLimitEntry {
	timestamps: number[]
}

/**
 * Pluggable backing store. Default: `MemoryRateLimitStore`. For multi-instance
 * deployments, supply a Redis-backed implementation that mirrors this contract.
 *
 * Note: only `incrementEntry` and `deleteEntry` are exercised by the limiter
 * today. `getEntry` is provided for adapters that want to read without writing.
 */
export interface RateLimitStore {
	getEntry(key: string): Promise<RateLimitEntry | null> | RateLimitEntry | null
	incrementEntry(
		key: string,
		timestamp: number,
		ttlMs: number,
		maxEntries?: number
	): Promise<RateLimitEntry> | RateLimitEntry
	deleteEntry(key: string): Promise<void> | void
}

export interface RateLimitWindow {
	/** Human label, e.g. `'short'`, `'long'`. */
	name: string
	/** Window length in ms. */
	windowMs: number
	/** Max events permitted per identifier within the window. */
	maxEvents: number
}

export interface RateLimitConfig {
	/** One or more sliding windows. ALL must be satisfied to allow a request. */
	windows: RateLimitWindow[]
	/** Pluggable store. Default: in-memory. */
	store?: RateLimitStore
	/** Pluggable logger. Default: silent. */
	logger?: Logger
	/** Namespace prefix for keys (useful when sharing a store across actions). */
	keyPrefix?: string
}

export type RateLimitResult =
	| { allowed: true; remaining: number; resetAtMs: number; window?: string }
	| { allowed: false; retryAfterSec: number; resetAtMs: number; window: string }

export interface RateLimiter {
	check(identifier: string): Promise<RateLimitResult>
	reset(identifier: string): Promise<void>
	readonly config: Readonly<RateLimitConfig>
}

/**
 * In-memory rate limit store.
 *
 * **Suitable only for single-instance deployments.** Multi-pod / multi-process
 * deployments must supply a Redis (or equivalent shared) store — each replica
 * holds an independent counter, defeating the rate limit.
 *
 * Includes opportunistic cleanup (~1% chance per increment) to bound memory.
 * For high-throughput services, call `cleanup(maxAgeMs)` periodically as well.
 */
export class MemoryRateLimitStore implements RateLimitStore {
	private readonly map = new Map<string, RateLimitEntry>()
	private readonly cleanupProbability: number

	constructor(options: { cleanupProbability?: number } = {}) {
		this.cleanupProbability = options.cleanupProbability ?? 0.01
	}

	get size(): number {
		return this.map.size
	}

	getEntry(key: string): RateLimitEntry | null {
		return this.map.get(key) ?? null
	}

	incrementEntry(key: string, timestamp: number, ttlMs: number, maxEntries?: number): RateLimitEntry {
		const cutoff = timestamp - ttlMs
		const existing = this.map.get(key)
		const timestamps = existing
			? existing.timestamps.filter(t => t > cutoff)
			: []
		timestamps.push(timestamp)
		if (maxEntries !== undefined && timestamps.length > maxEntries) {
			timestamps.splice(0, timestamps.length - maxEntries)
		}
		const entry: RateLimitEntry = { timestamps }
		this.map.set(key, entry)

		// Bound memory growth on attacker-controlled identifiers (e.g. IP rotation).
		if (Math.random() < this.cleanupProbability) {
			this.cleanup(ttlMs)
		}

		return entry
	}

	deleteEntry(key: string): void {
		this.map.delete(key)
	}

	/** Drop entries whose latest timestamp is older than `now - maxAgeMs`. */
	cleanup(maxAgeMs: number): number {
		const cutoff = Date.now() - maxAgeMs
		let removed = 0
		for (const [ key, entry ] of this.map.entries()) {
			const lastTimestamp = entry.timestamps[entry.timestamps.length - 1] ?? 0
			if (lastTimestamp < cutoff) {
				this.map.delete(key)
				removed++
			}
		}
		return removed
	}
}

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

	const log = resolveLogger(config.logger)
	const store = config.store ?? new MemoryRateLimitStore()
	const keyPrefix = config.keyPrefix ?? 'rate-limit'

	// Use the longest window as the storage TTL — covers all shorter windows.
	const maxWindowMs = Math.max(...config.windows.map(w => w.windowMs))
	const maxStoredEvents = Math.max(...config.windows.map(w => w.maxEvents + 1))

	function buildKey(identifier: string): string {
		return `${ keyPrefix }:${ identifier }`
	}

	async function check(identifier: string): Promise<RateLimitResult> {
		const key = buildKey(identifier)
		const now = Date.now()
		const entry = await store.incrementEntry(key, now, maxWindowMs, maxStoredEvents)

		let tightestRemaining = Number.POSITIVE_INFINITY
		let tightestResetAt = 0
		let tightestWindowName: string | null = null

		for (const window of config.windows) {
			const cutoff = now - window.windowMs
			const inWindow = entry.timestamps
				.filter(t => t > cutoff)
				.slice(-(window.maxEvents + 1))
			const remaining = window.maxEvents - inWindow.length

			if (inWindow.length > window.maxEvents) {
				// Limit exceeded for this window. retryAfter = when the oldest in-window
				// timestamp will roll out.
				const oldest = inWindow[0] ?? now
				const resetAt = oldest + window.windowMs
				log.warn(`Rate limit hit (window=${ window.name })`, {
					identifier,
					events: inWindow.length,
					maxEvents: window.maxEvents
				})
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

	async function reset(identifier: string): Promise<void> {
		await store.deleteEntry(buildKey(identifier))
	}

	return { check, reset, config }
}

/**
 * Options for `getClientIP`. You MUST explicitly opt in to trusting any
 * proxy header — otherwise the helper returns the literal `'unknown'`.
 * This default prevents attackers from spoofing identifiers via `x-forwarded-for`
 * when your service is not actually behind a known proxy.
 */
export interface GetClientIpOptions {
	/**
	 * Which proxy headers (if any) to honor. Order is preserved — the first
	 * header that's present wins. Default: `[]` (trust none).
	 *
	 * Only enable headers you know your trusted proxy sets, and confirm that
	 * your proxy strips any client-supplied values before adding its own.
	 *
	 * @example `['cf-connecting-ip']` for Cloudflare
	 * @example `['x-forwarded-for']` for AWS ALB / GCP LB (configured to strip)
	 * @example `['x-real-ip']` for Nginx with `proxy_set_header X-Real-IP`
	 */
	trustHeaders?: ReadonlyArray<'cf-connecting-ip' | 'x-forwarded-for' | 'x-real-ip'>
}

/**
 * Resolve the client IP from a Fetch-API `Request`.
 *
 * **By default, this trusts NO proxy headers** — it returns `'unknown'` unless
 * you explicitly opt in via `trustHeaders`. This is intentional: blindly
 * trusting `x-forwarded-for` is a common security mistake that turns rate
 * limiters into header-spoofable counters.
 *
 * When running in SvelteKit, prefer `event.getClientAddress()` — it consults
 * your platform adapter's trusted proxy config.
 *
 * @example
 * ```ts
 * // Cloudflare deployments:
 * const ip = getClientIP(event.request, { trustHeaders: ['cf-connecting-ip'] })
 *
 * // AWS ALB (configured to strip client-supplied XFF):
 * const ip = getClientIP(event.request, { trustHeaders: ['x-forwarded-for'] })
 *
 * // Direct-internet exposure (NO proxy):
 * // Don't use this helper; rely on event.getClientAddress() or socket.remoteAddress.
 * ```
 */
export function getClientIP(request: Request, options: GetClientIpOptions = {}): string {
	const trustHeaders = options.trustHeaders ?? []

	for (const headerName of trustHeaders) {
		const raw = request.headers.get(headerName)
		if (!raw) continue
		// x-forwarded-for can be a comma-separated chain; the first value is
		// (by convention) the original client.
		const first = raw.split(',')[0]
		if (first) {
			const trimmed = first.trim()
			if (trimmed) return trimmed
		}
	}

	return 'unknown'
}
