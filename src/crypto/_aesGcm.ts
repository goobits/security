import { hexToBytes } from './encoding.js'

type AesGcmKeyUsage = 'encrypt' | 'decrypt'

export function normalizeAesGcmKey(key: Uint8Array | string): Uint8Array {
	const bytes = typeof key === 'string' ? hexToBytes(key) : key
	if (![16, 24, 32].includes(bytes.length)) {
		throw new Error('@goobits/security/crypto: AES-GCM key must be 16, 24, or 32 bytes')
	}
	return bytes
}

export async function importAesGcmKey(
	key: Uint8Array | string,
	usage: AesGcmKeyUsage
): Promise<CryptoKey> {
	return crypto.subtle.importKey('raw', normalizeAesGcmKey(key) as never, 'AES-GCM', false, [usage])
}
