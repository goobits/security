import { getRandomBytes, timingSafeEqualBytes, toBytes, toHex } from '../_internal/crypto.js'
import type { IHasher } from 'hash-wasm'

export { getRandomBytes as randomBytes, toBytes as textToBytes, toHex as bytesToHex }

export type IncrementalHashAlgorithm = 'sha-256' | 'blake3'

export type IncrementalHasher = {
	update: (_bytes: Uint8Array) => void
	digestHex: () => string
}

/** Decodes UTF-8 bytes into text. */
export function bytesToText(bytes: Uint8Array): string {
	return new TextDecoder().decode(bytes)
}

/** Decodes a hex string into bytes. */
export function hexToBytes(value: string): Uint8Array {
	if (value.length % 2 !== 0) {
		throw new Error('@goobits/security/crypto: hex value must have an even length')
	}
	const bytes = new Uint8Array(value.length / 2)
	for (let i = 0; i < bytes.length; i += 1) {
		const pair = value.slice(i * 2, i * 2 + 2)
		if (!/^[0-9a-f]{2}$/i.test(pair)) {
			throw new Error('@goobits/security/crypto: invalid hex value')
		}
		bytes[i] = Number.parseInt(pair, 16)
	}
	return bytes
}

/** Generates cryptographically random bytes and returns them as hex. */
export function randomHex(byteLength = 32): string {
	return toHex(getRandomBytes(byteLength))
}

/** Encodes bytes as unpadded base64url. */
export function bytesToBase64Url(bytes: Uint8Array): string {
	let binary = ''
	for (let i = 0; i < bytes.length; i += 1) {
		binary += String.fromCharCode(bytes[i] ?? 0)
	}
	return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '')
}

/** Encodes bytes as canonical padded base64. */
export function bytesToBase64(bytes: Uint8Array): string {
	let binary = ''
	for (let i = 0; i < bytes.length; i += 1) {
		binary += String.fromCharCode(bytes[i] ?? 0)
	}
	return btoa(binary)
}

/** Decodes canonical padded base64 without accepting base64url or loose padding. */
export function base64ToBytes(value: string): Uint8Array {
	if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)) {
		throw new Error('@goobits/security/crypto: invalid base64 value')
	}
	let binary: string
	try {
		binary = atob(value)
	} catch {
		throw new Error('@goobits/security/crypto: invalid base64 value')
	}
	const bytes = new Uint8Array(binary.length)
	for (let i = 0; i < binary.length; i += 1) {
		bytes[i] = binary.charCodeAt(i)
	}
	if (bytesToBase64(bytes) !== value) {
		throw new Error('@goobits/security/crypto: invalid base64 value')
	}
	return bytes
}

/** Decodes unpadded base64url into bytes. */
export function base64UrlToBytes(value: string): Uint8Array {
	if (!/^[A-Za-z0-9_-]*$/u.test(value) || value.length % 4 === 1) {
		throw new Error('@goobits/security/crypto: invalid base64url value')
	}
	const normalized = value.replaceAll('-', '+').replaceAll('_', '/')
	const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), '=')
	let binary: string
	try {
		binary = atob(padded)
	} catch {
		throw new Error('@goobits/security/crypto: invalid base64url value')
	}
	const bytes = new Uint8Array(binary.length)
	for (let i = 0; i < binary.length; i += 1) {
		bytes[i] = binary.charCodeAt(i)
	}
	if (bytesToBase64Url(bytes) !== value) {
		throw new Error('@goobits/security/crypto: invalid base64url value')
	}
	return bytes
}

/** Compares byte or text values without leaking early mismatch timing. */
export function constantTimeEqual(left: Uint8Array | string, right: Uint8Array | string): boolean {
	const leftBytes = typeof left === 'string' ? toBytes(left) : left
	const rightBytes = typeof right === 'string' ? toBytes(right) : right
	return timingSafeEqualBytes(leftBytes, rightBytes)
}

/** Hashes bytes or text with SHA-256 and returns raw digest bytes. */
export async function sha256Bytes(value: Uint8Array | string): Promise<Uint8Array> {
	const data = typeof value === 'string' ? toBytes(value) : value
	const digest = await crypto.subtle.digest('SHA-256', data as never)
	return new Uint8Array(digest)
}

/** Hashes bytes or text with SHA-256 and returns a hex digest. */
export async function sha256Hex(value: Uint8Array | string): Promise<string> {
	return toHex(await sha256Bytes(value))
}

/** Creates a bounded-memory incremental hasher for streamed binary content. */
export async function createIncrementalHasher(
	algorithm: IncrementalHashAlgorithm
): Promise<IncrementalHasher> {
	const hasher = await createIncrementalHash(algorithm)
	hasher.init()
	let finished = false
	return {
		update(bytes) {
			if (finished) throw new Error('@goobits/security/crypto: incremental hash is finished')
			hasher.update(bytes)
		},
		digestHex() {
			if (finished) throw new Error('@goobits/security/crypto: incremental hash is finished')
			finished = true
			return hasher.digest('hex')
		}
	}
}

async function createIncrementalHash(algorithm: IncrementalHashAlgorithm): Promise<IHasher> {
	const { createBLAKE3, createSHA256 } = await import('hash-wasm')
	switch (algorithm) {
		case 'sha-256':
			return createSHA256()
		case 'blake3':
			return createBLAKE3()
	}
}
