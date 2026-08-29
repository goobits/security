import { reportDetachedError } from '../_reportDetachedError.js'

import type { RateLimitStore } from './types.js'

interface ResilientRateLimitStoreBaseOptions {
	primary: RateLimitStore
	onPrimaryError?: (operation: keyof RateLimitStore, error: unknown) => void | Promise<void>
}

/** Explicit availability policy for a primary rate-limit store failure. */
export type ResilientRateLimitStoreOptions = ResilientRateLimitStoreBaseOptions &
	({ failureMode: 'closed' } | { failureMode: 'fallback'; fallback: RateLimitStore })

/**
 * Uses a primary rate-limit store while making its failure policy explicit.
 * Closed mode propagates the original failure. Fallback mode delegates the
 * failed operation to the supplied fallback store. Observer failures are
 * intentionally isolated from both policies.
 */
export function createResilientRateLimitStore(
	options: ResilientRateLimitStoreOptions
): RateLimitStore {
	if (options.failureMode !== 'closed' && options.failureMode !== 'fallback') {
		throw new Error('createResilientRateLimitStore: failureMode must be closed or fallback')
	}
	if (options.failureMode === 'fallback' && !options.fallback) {
		throw new Error('createResilientRateLimitStore: fallback store is required in fallback mode')
	}

	const reportPrimaryError = (operation: keyof RateLimitStore, error: unknown): void => {
		try {
			const observation = options.onPrimaryError?.(operation, error)
			if (observation) {
				void Promise.resolve(observation).catch(observerError => {
					reportDetachedError('Rate-limit primary-error observer failed.', observerError)
				})
			}
		} catch(observerError) {
			reportDetachedError('Rate-limit primary-error observer failed.', observerError)
		}
	}

	return {
		async getEntry(key) {
			try {
				return await options.primary.getEntry(key)
			} catch (error) {
				reportPrimaryError('getEntry', error)
				if (options.failureMode === 'closed') throw error
				return options.fallback.getEntry(key)
			}
		},

		async incrementEntry(key, timestamp, ttlMs, maxEntries) {
			try {
				return await options.primary.incrementEntry(key, timestamp, ttlMs, maxEntries)
			} catch (error) {
				reportPrimaryError('incrementEntry', error)
				if (options.failureMode === 'closed') throw error
				return options.fallback.incrementEntry(key, timestamp, ttlMs, maxEntries)
			}
		},

		async deleteEntry(key) {
			try {
				await options.primary.deleteEntry(key)
			} catch (error) {
				reportPrimaryError('deleteEntry', error)
				if (options.failureMode === 'closed') throw error
			}
			if (options.failureMode === 'fallback') await options.fallback.deleteEntry(key)
		}
	}
}
