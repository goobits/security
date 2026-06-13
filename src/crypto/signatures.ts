import {
	base64UrlToBytes,
	bytesToBase64Url,
	constantTimeEqual,
	textToBytes
} from './encoding.js'

export type HmacAlgorithm = 'HS256' | 'HS384' | 'HS512'

export interface HmacSignature {
	algorithm: HmacAlgorithm
	value: string
}

const HMAC_HASH: Record<HmacAlgorithm, string> = {
	HS256: 'SHA-256',
	HS384: 'SHA-384',
	HS512: 'SHA-512'
}

function secretToBytes(secret: Uint8Array | string): Uint8Array {
	return typeof secret === 'string' ? textToBytes(secret) : secret
}

async function importHmacKey(
	secret: Uint8Array | string,
	algorithm: HmacAlgorithm
): Promise<CryptoKey> {
	return crypto.subtle.importKey(
		'raw',
		secretToBytes(secret) as unknown as BufferSource,
		{ name: 'HMAC', hash: HMAC_HASH[algorithm] },
		false,
		[ 'sign', 'verify' ]
	)
}

export async function signHmac(
	payload: Uint8Array | string,
	secret: Uint8Array | string,
	algorithm: HmacAlgorithm = 'HS256'
): Promise<HmacSignature> {
	const key = await importHmacKey(secret, algorithm)
	const data = typeof payload === 'string' ? textToBytes(payload) : payload
	const signature = await crypto.subtle.sign('HMAC', key, data as unknown as BufferSource)
	return {
		algorithm,
		value: bytesToBase64Url(new Uint8Array(signature))
	}
}

export async function verifyHmac(
	payload: Uint8Array | string,
	signature: HmacSignature,
	secret: Uint8Array | string
): Promise<boolean> {
	const expected = await signHmac(payload, secret, signature.algorithm)
	return constantTimeEqual(base64UrlToBytes(expected.value), base64UrlToBytes(signature.value))
}
