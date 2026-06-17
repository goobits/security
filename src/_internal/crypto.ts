/**
 * Cross-runtime crypto helpers.
 *
 * Supports Node.js (>=22, native Web Crypto in globalThis) and Cloudflare
 * Workers / Deno / Bun. All callers assume the modern Web Crypto API is
 * available on `globalThis.crypto`.
 *
 * @internal
 */

type CryptoLike = { getRandomValues<T extends ArrayBufferView | null>(array: T): T }

function getCryptoImpl(): CryptoLike {
	const candidate: unknown = (globalThis as unknown as { crypto?: CryptoLike }).crypto
	if (candidate && typeof (candidate as CryptoLike).getRandomValues === 'function') {
		return candidate as CryptoLike
	}
	throw new Error(
		'@goobits/security: Web Crypto API not available on globalThis.crypto. ' +
		'Requires Node.js >= 22, Bun, Deno, or Cloudflare Workers runtime.'
	)
}

export function getRandomBytes(length: number): Uint8Array {
	const bytes = new Uint8Array(length)
	getCryptoImpl().getRandomValues(bytes)
	return bytes
}

export function toHex(bytes: Uint8Array): string {
	let out = ''
	for (let i = 0; i < bytes.length; i++) {
		out += bytes[i]!.toString(16).padStart(2, '0')
	}
	return out
}

export function toBytes(value: string): Uint8Array {
	const encoder = (globalThis as unknown as { TextEncoder?: typeof TextEncoder }).TextEncoder
	if (encoder) {
		return new encoder().encode(value)
	}
	const out = new Uint8Array(value.length)
	for (let i = 0; i < value.length; i++) {
		out[i] = value.charCodeAt(i)
	}
	return out
}

/**
 * Constant-time byte comparison. Returns true iff both arrays have the
 * same length AND the same contents.
 */
export function timingSafeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false

	let result = 0
	for (let i = 0; i < a.length; i++) {
		result |= a[i]! ^ b[i]!
	}
	return result === 0
}
