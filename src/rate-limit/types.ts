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
