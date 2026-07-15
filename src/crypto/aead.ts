import {
	base64UrlToBytes,
	bytesToBase64Url,
	bytesToHex,
	bytesToText,
	hexToBytes,
	randomBytes,
	textToBytes
} from './encoding.js'

type AesKeyUsage = 'encrypt' | 'decrypt'
const AES_KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/

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

/** Opaque AES-GCM keyring. Key material remains private to this module. */
export interface AesGcmKeyring {
	readonly activeKeyId: string
}

/** Inputs for building a rotation-ready AES-GCM keyring. */
export interface AesGcmKeyringConfig {
	activeKeyId: string
	keys: Readonly<Record<string, Uint8Array | string>>
}

/** JSON representation accepted by `createAesGcmKeyringFromJson`. */
export interface AesGcmKeyringJsonConfig {
	activeKeyId: string
	keys: Readonly<Record<string, string>>
}

/** AES-GCM seal paired with the key ID needed to open it. */
export interface AesGcmKeyringSeal {
	keyId: string
	seal: AesGcmSeal
}

/** Inputs for sealing data with the active keyring key. */
export interface AesGcmKeyringSealOptions {
	keyring: AesGcmKeyring
	plaintext: Uint8Array | string
	associatedData?: Uint8Array | string
}

/** Inputs for opening data with the recorded keyring key. */
export interface AesGcmKeyringOpenOptions {
	keyring: AesGcmKeyring
	sealed: AesGcmKeyringSeal
	associatedData?: Uint8Array | string
}

const keyringEntries = new WeakMap<AesGcmKeyring, ReadonlyMap<string, Uint8Array>>()

function normalizeKey(key: Uint8Array | string): Uint8Array {
	const bytes = typeof key === 'string' ? hexToBytes(key) : key
	if (![16, 24, 32].includes(bytes.length)) {
		throw new Error('@goobits/security/crypto: AES-GCM key must be 16, 24, or 32 bytes')
	}
	return bytes
}

function assertKeyId(keyId: string): void {
	if (!AES_KEY_ID_PATTERN.test(keyId)) {
		throw new Error('@goobits/security/crypto: invalid AES-GCM key ID')
	}
}

/** Creates an opaque keyring with one active encryption key and optional retired decryption keys. */
export function createAesGcmKeyring(config: AesGcmKeyringConfig): AesGcmKeyring {
	assertKeyId(config.activeKeyId)
	const entries = Object.entries(config.keys)
	if (entries.length === 0) {
		throw new Error('@goobits/security/crypto: AES-GCM keyring requires at least one key')
	}

	const keys = new Map<string, Uint8Array>()
	const keyMaterials = new Set<string>()
	for (const [keyId, keyValue] of entries) {
		assertKeyId(keyId)
		const key = normalizeKey(keyValue).slice()
		const canonical = bytesToHex(key)
		if (keyMaterials.has(canonical)) {
			throw new Error('@goobits/security/crypto: AES-GCM keyring keys must be distinct')
		}
		keyMaterials.add(canonical)
		keys.set(keyId, key)
	}
	if (!keys.has(config.activeKeyId)) {
		throw new Error('@goobits/security/crypto: active AES-GCM key ID is not configured')
	}

	const keyring = Object.freeze({ activeKeyId: config.activeKeyId })
	keyringEntries.set(keyring, keys)
	return keyring
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** Parses a strict JSON keyring whose key values are hex-encoded AES keys. */
export function createAesGcmKeyringFromJson(json: string): AesGcmKeyring {
	let parsed: unknown
	try {
		parsed = JSON.parse(json)
	} catch {
		throw new Error('@goobits/security/crypto: invalid AES-GCM keyring JSON')
	}
	if (!isRecord(parsed) || typeof parsed['activeKeyId'] !== 'string' || !isRecord(parsed['keys'])) {
		throw new Error('@goobits/security/crypto: invalid AES-GCM keyring JSON')
	}
	const unknownFields = Object.keys(parsed).filter(
		(field) => field !== 'activeKeyId' && field !== 'keys'
	)
	if (unknownFields.length > 0) {
		throw new Error('@goobits/security/crypto: invalid AES-GCM keyring JSON')
	}
	const keys: Record<string, string> = {}
	for (const [keyId, value] of Object.entries(parsed['keys'])) {
		if (typeof value !== 'string') {
			throw new Error('@goobits/security/crypto: invalid AES-GCM keyring JSON')
		}
		keys[keyId] = value
	}
	return createAesGcmKeyring({ activeKeyId: parsed['activeKeyId'], keys })
}

/** Returns whether a key ID is present without exposing its key material. */
export function hasAesGcmKey(keyring: AesGcmKeyring, keyId: string): boolean {
	return AES_KEY_ID_PATTERN.test(keyId) && keyringEntries.get(keyring)?.has(keyId) === true
}

function keyFor(keyring: AesGcmKeyring, keyId: string): Uint8Array {
	assertKeyId(keyId)
	const key = keyringEntries.get(keyring)?.get(keyId)
	if (!key) throw new Error('@goobits/security/crypto: AES-GCM key is not configured')
	return key
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

/** Seals data with the keyring's active key and records only its public key ID. */
export async function sealAesGcmWithKeyring(
	options: AesGcmKeyringSealOptions
): Promise<AesGcmKeyringSeal> {
	const keyId = options.keyring.activeKeyId
	return {
		keyId,
		seal: await sealAesGcm({
			key: keyFor(options.keyring, keyId),
			plaintext: options.plaintext,
			...(options.associatedData !== undefined ? { associatedData: options.associatedData } : {})
		})
	}
}

/** Opens a keyring seal using its recorded key ID. */
export async function openAesGcmWithKeyring(
	options: AesGcmKeyringOpenOptions
): Promise<Uint8Array> {
	return await openAesGcm({
		key: keyFor(options.keyring, options.sealed.keyId),
		seal: options.sealed.seal,
		...(options.associatedData !== undefined ? { associatedData: options.associatedData } : {})
	})
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
