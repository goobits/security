/**
 * Rate limiting  -  sliding-window counter with pluggable store.
 *
 * @module @goobits/security/rate-limit
 */

import { resolveLogger } from '../_internal/resolveLogger.js'
import { signHmac, textToBytes } from '../crypto/index.js'
import type { Logger } from '../logger.js'

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

/** Configuration for a rate-limit store that pseudonymizes identifiers before persistence. */
export interface HmacRateLimitStoreOptions {
	store: RateLimitStore
	secret: Uint8Array | string
	namespace?: string
}

/**
 * Wraps a rate-limit store so raw IPs, emails, usernames, and tokens are never
 * persisted as keys. Store failures deliberately propagate to the caller,
 * which remains responsible for its fail-open or fail-closed route policy.
 */
export function createHmacRateLimitStore({
	store,
	secret,
	namespace = 'rate-limit:v1'
}: HmacRateLimitStoreOptions): RateLimitStore {
	const secretLength =
		typeof secret === 'string' ? textToBytes(secret).byteLength : secret.byteLength
	if (secretLength < 32) {
		throw new Error('createHmacRateLimitStore: secret must be at least 32 bytes')
	}
	if (!namespace || namespace.length > 128 || namespace.includes('\0')) {
		throw new Error('createHmacRateLimitStore: namespace must be 1-128 characters without NUL')
	}

	const storageKey = async (key: string): Promise<string> => {
		const signature = await signHmac(`${namespace}\0${key}`, secret, 'HS256')
		return `hmac:v1:${signature.value}`
	}

	return {
		async getEntry(key) {
			return store.getEntry(await storageKey(key))
		},
		async incrementEntry(key, timestamp, ttlMs, maxEntries) {
			return store.incrementEntry(await storageKey(key), timestamp, ttlMs, maxEntries)
		},
		async deleteEntry(key) {
			await store.deleteEntry(await storageKey(key))
		}
	}
}

/** Minimal Cloudflare D1-compatible database shape used by `D1RateLimitStore`. */
export interface D1RateLimitDatabase {
	prepare(sql: string): {
		bind(...args: unknown[]): {
			first<T = Record<string, unknown>>(): Promise<T | null>
			run(): Promise<unknown>
		}
	}
}

export interface D1RateLimitStoreOptions {
	table?: string
	columns?: Partial<{
		key: string
		count: string
		resetAt: string
	}>
}

const DEFAULT_D1_RATE_LIMIT_COLUMNS = {
	key: 'key',
	count: 'count',
	resetAt: 'reset_at'
} as const
type D1RateLimitColumns = {
	key: string
	count: string
	resetAt: string
}

function quoteD1Identifier(identifier: string): string {
	if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(identifier)) {
		throw new Error(`D1RateLimitStore: invalid SQL identifier "${identifier}"`)
	}
	return `"${identifier}"`
}

/**
 * D1-backed rate limit store.
 *
 * Uses the common `rate_limits(key, count, reset_at)` table by default. The
 * `count` column stores JSON timestamp arrays for sliding-window precision.
 */
export class D1RateLimitStore implements RateLimitStore {
	private readonly table: string
	private readonly columns: D1RateLimitColumns

	constructor(
		private readonly db: D1RateLimitDatabase,
		options: D1RateLimitStoreOptions = {}
	) {
		this.table = quoteD1Identifier(options.table ?? 'rate_limits')
		this.columns = {
			...DEFAULT_D1_RATE_LIMIT_COLUMNS,
			...options.columns
		}
		for (const column of Object.values(this.columns)) quoteD1Identifier(column)
	}

	private mapEntry(
		row: { count: number | string | null; reset_at: number | string | null } | null,
		now = Date.now()
	): RateLimitEntry | null {
		if (!row) return null
		const resetAtMs = Number(row.reset_at ?? 0) * 1000
		if (!Number.isFinite(resetAtMs) || resetAtMs <= now) return null

		const raw = row.count
		if (typeof raw === 'string') {
			try {
				const parsed = JSON.parse(raw) as unknown
				if (
					Array.isArray(parsed) &&
					parsed.every((value) => typeof value === 'number' && Number.isFinite(value))
				) {
					return { timestamps: parsed }
				}
			} catch {
				return null
			}
		}

		return null
	}

	async getEntry(key: string): Promise<RateLimitEntry | null> {
		const keyColumn = quoteD1Identifier(this.columns.key)
		const countColumn = quoteD1Identifier(this.columns.count)
		const resetAtColumn = quoteD1Identifier(this.columns.resetAt)
		const row = await this.db
			.prepare(
				`SELECT ${countColumn} AS count, ${resetAtColumn} AS reset_at
				 FROM ${this.table}
				 WHERE ${keyColumn} = ? LIMIT 1`
			)
			.bind(key)
			.first<{ count: number | string | null; reset_at: number | string | null }>()
		const entry = this.mapEntry(row)
		if (!row || entry) return entry
		await this.deleteEntry(key)
		return null
	}

	async incrementEntry(
		key: string,
		timestamp: number,
		ttlMs: number,
		maxEntries?: number
	): Promise<RateLimitEntry> {
		const keyColumn = quoteD1Identifier(this.columns.key)
		const countColumn = quoteD1Identifier(this.columns.count)
		const resetAtColumn = quoteD1Identifier(this.columns.resetAt)
		const cutoff = timestamp - ttlMs
		const retainedLimit = maxEntries === undefined ? -1 : Math.max(0, maxEntries - 1)
		const resetAtSeconds = Math.ceil((timestamp + ttlMs) / 1000)
		const row = await this.db
			.prepare(
				`INSERT INTO ${this.table} (${keyColumn}, ${countColumn}, ${resetAtColumn})
				 VALUES (?, json_array(?), ?)
				 ON CONFLICT(${keyColumn}) DO UPDATE SET
					${countColumn} = json_insert(
						(
							SELECT json_group_array(value)
							FROM (
								SELECT value, position
								FROM (
									SELECT CAST(value AS INTEGER) AS value, CAST(key AS INTEGER) AS position
									FROM json_each(
										CASE
											WHEN CAST(${this.table}.${resetAtColumn} AS INTEGER) * 1000 <= ? THEN json_array()
											WHEN json_valid(${this.table}.${countColumn}) AND json_type(${this.table}.${countColumn}) = 'array'
												THEN ${this.table}.${countColumn}
											ELSE json_array()
										END
									)
									WHERE CAST(value AS REAL) > ?
									ORDER BY position DESC
									LIMIT ?
								)
								ORDER BY position
							)
						),
						'$[#]',
						?
					),
					${resetAtColumn} = excluded.${resetAtColumn}
				 RETURNING ${countColumn} AS count, ${resetAtColumn} AS reset_at`
			)
			.bind(
				key,
				timestamp,
				resetAtSeconds,
				timestamp,
				cutoff,
				retainedLimit,
				timestamp
			)
			.first<{ count: number | string | null; reset_at: number | string | null }>()
		const entry = this.mapEntry(row, timestamp)
		if (!entry) throw new Error('D1RateLimitStore: increment did not return a valid entry')
		return entry
	}

	async deleteEntry(key: string): Promise<void> {
		const keyColumn = quoteD1Identifier(this.columns.key)
		await this.db.prepare(`DELETE FROM ${this.table} WHERE ${keyColumn} = ?`).bind(key).run()
	}
}

/** Rate Limit Window request or option shape for rate limiting. */
export interface RateLimitWindow {
	/** Human label, e.g. `'short'`, `'long'`. */
	name: string
	/** Window length in ms. */
	windowMs: number
	/** Max events permitted per identifier within the window. */
	maxEvents: number
}

/** Rate Limit Config request or option shape for rate limiting. */
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

/** Rate Limit Result typed model for rate limiting. */
export type RateLimitResult =
	| { allowed: true; remaining: number; resetAtMs: number; window?: string }
	| { allowed: false; retryAfterSec: number; resetAtMs: number; window: string }

/** Rate Limiter request or option shape for rate limiting. */
export interface RateLimiter {
	check(identifier: string): Promise<RateLimitResult>
	/**
	 * Non-incrementing read of the current rate-limit verdict  -  useful for
	 * response headers (`X-RateLimit-Remaining`, `X-RateLimit-Reset`) where
	 * you want to surface quota without consuming one. Returns the same
	 * `RateLimitResult` shape as `check()` based on the current stored
	 * timestamps, but does NOT call `incrementEntry`.
	 *
	 * If no entry exists for the identifier yet, returns
	 * `{ allowed: true, remaining: <tightest window maxEvents>, resetAtMs: now + <tightest window> }`.
	 */
	peek(identifier: string): Promise<RateLimitResult>
	reset(identifier: string): Promise<void>
	readonly config: Readonly<RateLimitConfig>
}

/** Configures the bounded in-memory rate-limit store. */
export interface MemoryRateLimitStoreOptions {
	/** Probability of opportunistic stale-entry cleanup per increment. Default: 0.01. */
	cleanupProbability?: number
	/** Maximum number of identifiers retained in memory. Default: 10,000. */
	maxKeys?: number
}

/**
 * In-memory rate limit store.
 *
 * **Suitable only for single-instance deployments.** Multi-pod / multi-process
 * deployments must supply a Redis (or equivalent shared) store  -  each replica
 * holds an independent counter, defeating the rate limit.
 *
 * Includes opportunistic cleanup (~1% chance per increment) to bound memory.
 * For high-throughput services, call `cleanup(maxAgeMs)` periodically as well.
 */
export class MemoryRateLimitStore implements RateLimitStore {
	private readonly map = new Map<string, RateLimitEntry>()
	private readonly cleanupProbability: number
	private readonly maxKeys: number

	constructor(options: MemoryRateLimitStoreOptions = {}) {
		const cleanupProbability = options.cleanupProbability ?? 0.01
		if (!Number.isFinite(cleanupProbability) || cleanupProbability < 0 || cleanupProbability > 1) {
			throw new Error('MemoryRateLimitStore: cleanupProbability must be between 0 and 1')
		}
		const maxKeys = options.maxKeys ?? 10_000
		if (!Number.isSafeInteger(maxKeys) || maxKeys <= 0) {
			throw new Error('MemoryRateLimitStore: maxKeys must be a positive safe integer')
		}
		this.cleanupProbability = cleanupProbability
		this.maxKeys = maxKeys
	}

	get size(): number {
		return this.map.size
	}

	getEntry(key: string): RateLimitEntry | null {
		return this.map.get(key) ?? null
	}

	incrementEntry(
		key: string,
		timestamp: number,
		ttlMs: number,
		maxEntries?: number
	): RateLimitEntry {
		const cutoff = timestamp - ttlMs
		const existing = this.map.get(key)
		if (!existing && this.map.size >= this.maxKeys) {
			this.cleanup(ttlMs)
			while (this.map.size >= this.maxKeys) {
				const oldest = this.map.keys().next()
				if (oldest.done) break
				this.map.delete(oldest.value)
			}
		}
		const timestamps = existing ? existing.timestamps.filter((t) => t > cutoff) : []
		timestamps.push(timestamp)
		if (maxEntries !== undefined && timestamps.length > maxEntries) {
			timestamps.splice(0, timestamps.length - maxEntries)
		}
		const entry: RateLimitEntry = { timestamps }
		if (existing) this.map.delete(key)
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
		for (const [key, entry] of this.map.entries()) {
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

/**
 * Options for `getClientIP`. You MUST explicitly opt in to trusting any
 * proxy header  -  otherwise the helper returns the literal `'unknown'`.
 * This default prevents attackers from spoofing identifiers via `x-forwarded-for`
 * when your service is not actually behind a known proxy.
 */
export interface GetClientIpOptions {
	/**
	 * Which proxy headers (if any) to honor. Order is preserved  -  the first
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

function normalizeClientIp(value: string): string | null {
	const candidate = value.trim()
	if (!candidate || candidate.length > 64 || /[\s\u0000-\u001f\u007f]/u.test(candidate)) {
		return null
	}

	if (/^\d{1,3}(?:\.\d{1,3}){3}$/u.test(candidate)) {
		return candidate
			.split('.')
			.every((part) => Number(part) >= 0 && Number(part) <= 255)
			? candidate
			: null
	}

	if (!candidate.includes(':') || !/^[0-9A-Fa-f:.]+$/u.test(candidate)) return null
	try {
		const parsed = new URL(`http://[${candidate}]/`)
		return parsed.hostname.length > 2 ? candidate : null
	} catch {
		return null
	}
}

/**
 * Resolve the client IP from a Fetch-API `Request`.
 *
 * **By default, this trusts NO proxy headers**  -  it returns `'unknown'` unless
 * you explicitly opt in via `trustHeaders`. This is intentional: blindly
 * trusting `x-forwarded-for` is a common security mistake that turns rate
 * limiters into header-spoofable counters.
 *
 * When running in SvelteKit, prefer `event.getClientAddress()`  -  it consults
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
			const normalized = normalizeClientIp(first)
			if (normalized) return normalized
		}
	}

	return 'unknown'
}
