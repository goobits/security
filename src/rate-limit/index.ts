/**
 * Rate limiting  -  sliding-window counter with pluggable store.
 *
 * @module @goobits/security/rate-limit
 */

export type {
	RateLimitConfig,
	RateLimitEntry,
	RateLimitResult,
	RateLimitStore,
	RateLimitWindow,
	RateLimiter
} from './types.js'
export {
	createResilientRateLimitStore,
	type ResilientRateLimitStoreOptions
} from './resilientStore.js'
export { createHmacRateLimitStore, type HmacRateLimitStoreOptions } from './hmacStore.js'
export {
	D1RateLimitStore,
	type D1RateLimitDatabase,
	type D1RateLimitStoreOptions
} from './d1Store.js'
export { MemoryRateLimitStore, type MemoryRateLimitStoreOptions } from './memoryStore.js'
export { createRateLimiter } from './limiter.js'
export { getClientIP, type GetClientIpOptions } from './clientIp.js'
