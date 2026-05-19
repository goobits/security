/**
 * Auth-flow rate limiting — pre-baked limiters tuned for login + registration.
 *
 * Defaults are conservative; tune as needed for your traffic.
 *
 * @module @goobits/security/rate-limit/auth
 */

import type { Logger } from '../logger.js'

import { createRateLimiter, type RateLimiter, type RateLimitStore } from './index.js'

export interface AuthRateLimitConfig {
	store?: RateLimitStore
	logger?: Logger
	keyPrefix?: string
}

/**
 * Login attempts: tight per-IP/identity throttle.
 *
 * Default windows:
 *   - 5 attempts per minute  (block bursts)
 *   - 15 attempts per 15 min (slow brute-force)
 */
export function createLoginRateLimiter(config: AuthRateLimitConfig = {}): RateLimiter {
	const limiterConfig: Parameters<typeof createRateLimiter>[0] = {
		windows: [
			{ name: 'login:burst', windowMs: 60_000, maxEvents: 5 },
			{ name: 'login:hour', windowMs: 15 * 60_000, maxEvents: 15 }
		],
		keyPrefix: config.keyPrefix ?? 'auth:login'
	}
	if (config.store) limiterConfig.store = config.store
	if (config.logger) limiterConfig.logger = config.logger
	return createRateLimiter(limiterConfig)
}

/**
 * Registration: looser than login (real users register a few times max).
 *
 * Default windows:
 *   - 3 registrations per 10 minutes
 *   - 5 registrations per hour
 */
export function createRegistrationRateLimiter(config: AuthRateLimitConfig = {}): RateLimiter {
	const limiterConfig: Parameters<typeof createRateLimiter>[0] = {
		windows: [
			{ name: 'register:ten-min', windowMs: 10 * 60_000, maxEvents: 3 },
			{ name: 'register:hour', windowMs: 60 * 60_000, maxEvents: 5 }
		],
		keyPrefix: config.keyPrefix ?? 'auth:register'
	}
	if (config.store) limiterConfig.store = config.store
	if (config.logger) limiterConfig.logger = config.logger
	return createRateLimiter(limiterConfig)
}

/**
 * Password reset: very tight (one of the most-abused auth flows).
 *
 * Default windows:
 *   - 3 requests per 15 minutes
 *   - 5 requests per hour
 */
export function createPasswordResetRateLimiter(config: AuthRateLimitConfig = {}): RateLimiter {
	const limiterConfig: Parameters<typeof createRateLimiter>[0] = {
		windows: [
			{ name: 'password-reset:fifteen-min', windowMs: 15 * 60_000, maxEvents: 3 },
			{ name: 'password-reset:hour', windowMs: 60 * 60_000, maxEvents: 5 }
		],
		keyPrefix: config.keyPrefix ?? 'auth:password-reset'
	}
	if (config.store) limiterConfig.store = config.store
	if (config.logger) limiterConfig.logger = config.logger
	return createRateLimiter(limiterConfig)
}
