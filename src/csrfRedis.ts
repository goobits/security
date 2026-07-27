/**
 * Redis-backed CSRF token store, for multi-instance deployments.
 *
 * Wraps any Redis-compatible client implementing `get`, `set`, `del`, and
 * `scan` in the
 * `CsrfTokenStore` interface from `@goobits/security/csrf`.
 *
 * @module @goobits/security/csrf-redis
 */

import type { CsrfTokenStore } from './csrf.js'
import { resolveLogger } from './_internal/resolveLogger.js'
import type { Logger } from './logger.js'
import { safeErrorContext } from './logger.js'

/** Minimal Redis client contract required by this adapter. */
export interface RedisLike {
	get(key: string): Promise<string | null>
	set(key: string, value: string, mode: 'PX', ttlMs: number): Promise<unknown>
	del(key: string): Promise<unknown>
	scan(
		cursor: string,
		matchMode: 'MATCH',
		pattern: string,
		countMode: 'COUNT',
		count: number
	): Promise<[string, string[]]>
}

/** Redis Csrf Store Options request or option shape for security middleware. */
export interface RedisCsrfStoreOptions {
	client: RedisLike
	keyPrefix?: string
	logger?: Logger
	clearScanCount?: number
	clearBatchSize?: number
}

/**
 * Build a Redis-backed `CsrfTokenStore`. Pass it to `createCsrf({ tokenStore })`.
 *
 * @example
 * ```ts
 * import Redis from 'ioredis' // Host-owned client; not a package dependency.
 * import { createCsrf } from '@goobits/security/csrf'
 * import { createRedisCsrfStore } from '@goobits/security/csrf-redis'
 *
 * const client = new Redis(process.env.REDIS_URL!)
 * const csrf = createCsrf({
 *   tokenStore: createRedisCsrfStore({ client })
 * })
 * ```
 */
export function createRedisCsrfStore(options: RedisCsrfStoreOptions): CsrfTokenStore {
	const { client } = options
	const keyPrefix = options.keyPrefix ?? 'csrf'
	const clearScanCount = options.clearScanCount ?? 500
	const clearBatchSize = options.clearBatchSize ?? 100
	const log = resolveLogger(options.logger)

	const key = (token: string): string => `${keyPrefix}:${token}`

	return {
		async get(token: string): Promise<number | undefined> {
			try {
				const raw = await client.get(key(token))
				if (raw === null) return undefined
				const parsed = Number(raw)
				return Number.isFinite(parsed) ? parsed : undefined
			} catch (err) {
				log.error('Redis CSRF store: get failed', safeErrorContext(err))
				throw err
			}
		},

		async set(token: string, expiresAt: number, ttlMs?: number): Promise<void> {
			const effectiveTtl = ttlMs ?? Math.max(1, expiresAt - Date.now())
			try {
				await client.set(key(token), String(expiresAt), 'PX', effectiveTtl)
			} catch (err) {
				log.error('Redis CSRF store: set failed', safeErrorContext(err))
				throw err
			}
		},

		async delete(token: string): Promise<void> {
			try {
				await client.del(key(token))
			} catch (err) {
				log.error('Redis CSRF store: delete failed', safeErrorContext(err))
				throw err
			}
		},

		async clear(): Promise<void> {
			try {
				let cursor = '0'
				do {
					const [nextCursor, keys] = await client.scan(
						cursor,
						'MATCH',
						`${keyPrefix}:*`,
						'COUNT',
						clearScanCount
					)
					cursor = nextCursor
					for (let i = 0; i < keys.length; i += clearBatchSize) {
						const batch = keys.slice(i, i + clearBatchSize)
						await Promise.all(batch.map((k) => client.del(k)))
					}
				} while (cursor !== '0')
			} catch (err) {
				log.error('Redis CSRF store: clear failed', safeErrorContext(err))
				throw err
			}
		}
	}
}
