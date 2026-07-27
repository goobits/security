import type { RateLimitEntry, RateLimitStore } from './types.js'

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
