import { signHmac, textToBytes } from '../crypto/index.js'
import type { RateLimitStore } from './types.js'

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
