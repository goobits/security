import {
	getRandomBytes,
	timingSafeEqualBytes,
	toBytes,
	toHex
} from '../_internal/crypto.js'

export { getRandomBytes as randomBytes, toBytes as textToBytes, toHex as bytesToHex }

export function bytesToText(bytes: Uint8Array): string {
	return new TextDecoder().decode(bytes)
}

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

export function randomHex(byteLength = 32): string {
	return toHex(getRandomBytes(byteLength))
}

export function bytesToBase64Url(bytes: Uint8Array): string {
	let binary = ''
	for (let i = 0; i < bytes.length; i += 1) {
		binary += String.fromCharCode(bytes[i] ?? 0)
	}
	return btoa(binary)
		.replaceAll('+', '-')
		.replaceAll('/', '_')
		.replace(/=+$/u, '')
}

export function base64UrlToBytes(value: string): Uint8Array {
	const normalized = value.replaceAll('-', '+').replaceAll('_', '/')
	const padded = normalized.padEnd(normalized.length + ((4 - normalized.length % 4) % 4), '=')
	const binary = atob(padded)
	const bytes = new Uint8Array(binary.length)
	for (let i = 0; i < binary.length; i += 1) {
		bytes[i] = binary.charCodeAt(i)
	}
	return bytes
}

export function constantTimeEqual(left: Uint8Array | string, right: Uint8Array | string): boolean {
	const leftBytes = typeof left === 'string' ? toBytes(left) : left
	const rightBytes = typeof right === 'string' ? toBytes(right) : right
	return timingSafeEqualBytes(leftBytes, rightBytes)
}

export async function sha256Bytes(value: Uint8Array | string): Promise<Uint8Array> {
	const data = typeof value === 'string' ? toBytes(value) : value
	const digest = await crypto.subtle.digest('SHA-256', data as unknown as BufferSource)
	return new Uint8Array(digest)
}

export async function sha256Hex(value: Uint8Array | string): Promise<string> {
	return toHex(await sha256Bytes(value))
}
