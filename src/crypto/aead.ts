import {
	base64UrlToBytes,
	bytesToBase64Url,
	bytesToText,
	hexToBytes,
	randomBytes,
	textToBytes
} from './encoding.js'

type AesKeyUsage = 'encrypt' | 'decrypt'

/** Serialized AES-GCM encrypted payload. */
export interface AesGcmSeal {
	algorithm: 'AES-GCM'
	iv: string
	ciphertext: string
}

/** Inputs for sealing bytes or text with AES-GCM. */
export interface AesGcmOptions {
	key: Uint8Array | string
	plaintext: Uint8Array | string
	associatedData?: Uint8Array | string
}

/** Inputs for opening an AES-GCM sealed payload. */
export interface AesGcmOpenOptions {
	key: Uint8Array | string
	seal: AesGcmSeal
	associatedData?: Uint8Array | string
}

function normalizeKey(key: Uint8Array | string): Uint8Array {
	const bytes = typeof key === 'string' ? hexToBytes(key) : key
	if (![16, 24, 32].includes(bytes.length)) {
		throw new Error('@goobits/security/crypto: AES-GCM key must be 16, 24, or 32 bytes')
	}
	return bytes
}

function normalizeData(value: Uint8Array | string | undefined): Uint8Array | undefined {
	if (value === undefined) return undefined
	return typeof value === 'string' ? textToBytes(value) : value
}

async function importAesKey(key: Uint8Array | string, usage: AesKeyUsage): Promise<CryptoKey> {
	return crypto.subtle.importKey('raw', normalizeKey(key) as never, 'AES-GCM', false, [usage])
}

/** Encrypts bytes or text with AES-GCM. */
export async function sealAesGcm(options: AesGcmOptions): Promise<AesGcmSeal> {
	const iv = randomBytes(12)
	const key = await importAesKey(options.key, 'encrypt')
	const associatedData = normalizeData(options.associatedData)
	const plaintext = normalizeData(options.plaintext) ?? new Uint8Array()
	const ciphertext = await crypto.subtle.encrypt(
		{
			name: 'AES-GCM',
			iv: iv as never,
			...(associatedData ? { additionalData: associatedData as never } : {})
		},
		key,
		plaintext as never
	)
	return {
		algorithm: 'AES-GCM',
		iv: bytesToBase64Url(iv),
		ciphertext: bytesToBase64Url(new Uint8Array(ciphertext))
	}
}

/** Decrypts an AES-GCM seal into raw bytes. */
export async function openAesGcm(options: AesGcmOpenOptions): Promise<Uint8Array> {
	if (options.seal.algorithm !== 'AES-GCM') {
		throw new Error('@goobits/security/crypto: unsupported AEAD algorithm')
	}
	const key = await importAesKey(options.key, 'decrypt')
	const associatedData = normalizeData(options.associatedData)
	const plaintext = await crypto.subtle.decrypt(
		{
			name: 'AES-GCM',
			iv: base64UrlToBytes(options.seal.iv) as never,
			...(associatedData ? { additionalData: associatedData as never } : {})
		},
		key,
		base64UrlToBytes(options.seal.ciphertext) as never
	)
	return new Uint8Array(plaintext)
}

/** JSON-serializes and encrypts a value with AES-GCM. */
export async function sealJson(
	value: unknown,
	options: Omit<AesGcmOptions, 'plaintext'>
): Promise<AesGcmSeal> {
	return sealAesGcm({
		...options,
		plaintext: JSON.stringify(value)
	})
}

/** Decrypts an AES-GCM seal and parses the plaintext as JSON. */
export async function openJson<T = unknown>(options: AesGcmOpenOptions): Promise<T> {
	const bytes = await openAesGcm(options)
	return JSON.parse(bytesToText(bytes)) as T
}
