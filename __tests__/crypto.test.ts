import { describe, expect, it } from 'vitest'

import {
	base64UrlToBytes,
	bytesToBase64Url,
	bytesToHex,
	bytesToText,
	constantTimeEqual,
	createAesGcmKeyring,
	createAesGcmKeyringFromJson,
	hasAesGcmKey,
	hexToBytes,
	openAesGcm,
	openAesGcmWithKeyring,
	openJson,
	randomBytes,
	randomHex,
	sealAesGcm,
	sealAesGcmWithKeyring,
	sealJson,
	sha256Hex,
	signHmac,
	textToBytes,
	verifyHmac
} from '../src/crypto/index.js'

describe('crypto encoding helpers', () => {
	it('round-trips text, hex, and base64url values', () => {
		const bytes = textToBytes('hello')
		expect(bytesToText(bytes)).toBe('hello')
		expect(bytesToHex(bytes)).toBe('68656c6c6f')
		expect(hexToBytes('68656c6c6f')).toEqual(bytes)
		expect(base64UrlToBytes(bytesToBase64Url(bytes))).toEqual(bytes)
	})

	it('rejects malformed and non-canonical base64url values', () => {
		for (const value of ['a', 'abc=', 'abc+', 'abc/', 'ab c', 'AB==']) {
			expect(() => base64UrlToBytes(value)).toThrow(/invalid base64url/)
		}
	})

	it('generates random bytes and hex', () => {
		expect(randomBytes(16)).toHaveLength(16)
		expect(randomHex(16)).toMatch(/^[0-9a-f]{32}$/)
	})

	it('hashes with sha256', async () => {
		expect(await sha256Hex('hello')).toBe(
			'2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
		)
	})

	it('compares values in constant-time byte loops', () => {
		expect(constantTimeEqual('abc', 'abc')).toBe(true)
		expect(constantTimeEqual('abc', 'abd')).toBe(false)
	})
})

describe('crypto signatures', () => {
	it('signs and verifies HMAC payloads', async () => {
		const signature = await signHmac('payload', 'secret')

		expect(signature.algorithm).toBe('HS256')
		expect(await verifyHmac('payload', signature, 'secret')).toBe(true)
		expect(await verifyHmac('tampered', signature, 'secret')).toBe(false)
	})

	it('treats malformed HMAC signatures as invalid instead of throwing', async () => {
		await expect(
			verifyHmac('payload', { algorithm: 'HS256', value: 'not+base64url' }, 'secret')
		).resolves.toBe(false)
		await expect(
			verifyHmac(
				'payload',
				{ algorithm: 'invalid' as 'HS256', value: 'abc' },
				'secret'
			)
		).resolves.toBe(false)
	})
})

describe('crypto AEAD helpers', () => {
	it('seals and opens bytes with AES-GCM', async () => {
		const key = randomHex(32)
		const seal = await sealAesGcm({
			key,
			plaintext: 'secret',
			associatedData: 'auth-context'
		})
		const opened = await openAesGcm({
			key,
			seal,
			associatedData: 'auth-context'
		})

		expect(bytesToText(opened)).toBe('secret')
	})

	it('rejects tampered associated data', async () => {
		const key = randomHex(32)
		const seal = await sealAesGcm({
			key,
			plaintext: 'secret',
			associatedData: 'auth-context'
		})

		await expect(
			openAesGcm({
				key,
				seal,
				associatedData: 'other-context'
			})
		).rejects.toThrow()
	})

	it('seals and opens JSON values', async () => {
		const key = randomHex(32)
		const seal = await sealJson({ token: 'abc' }, { key })

		await expect(openJson<{ token: string }>({ key, seal })).resolves.toEqual({ token: 'abc' })
	})

	it('rotates opaque keyrings without exposing key material', async () => {
		const oldKey = randomHex(32)
		const currentKey = randomHex(32)
		const oldKeyring = createAesGcmKeyring({ activeKeyId: 'old', keys: { old: oldKey } })
		const sealed = await sealAesGcmWithKeyring({
			keyring: oldKeyring,
			plaintext: 'secret',
			associatedData: 'context'
		})
		const rotatedKeyring = createAesGcmKeyring({
			activeKeyId: 'current',
			keys: { old: oldKey, current: currentKey }
		})

		expect(rotatedKeyring).toEqual({ activeKeyId: 'current' })
		expect(hasAesGcmKey(rotatedKeyring, 'old')).toBe(true)
		expect(
			bytesToText(
				await openAesGcmWithKeyring({
					keyring: rotatedKeyring,
					sealed,
					associatedData: 'context'
				})
			)
		).toBe('secret')
	})

	it('builds the same opaque keyring from strict JSON configuration', async () => {
		const oldKey = randomHex(32)
		const currentKey = randomHex(32)
		const keyring = createAesGcmKeyringFromJson(
			JSON.stringify({
				activeKeyId: 'current',
				keys: { old: oldKey, current: currentKey }
			})
		)
		const sealed = await sealAesGcmWithKeyring({ keyring, plaintext: 'secret' })

		expect(keyring).toEqual({ activeKeyId: 'current' })
		expect(sealed.keyId).toBe('current')
		expect(bytesToText(await openAesGcmWithKeyring({ keyring, sealed }))).toBe('secret')
	})

	it('rejects malformed or ambiguous keyring JSON without echoing secrets', () => {
		for (const input of [
			'not-json-secret-value',
			'[]',
			JSON.stringify({ activeKeyId: 'current', keys: { current: 123 } }),
			JSON.stringify({ activeKeyId: 'current', keys: {}, typo: 'secret-value' })
		]) {
			expect(() => createAesGcmKeyringFromJson(input)).toThrow(/invalid AES-GCM keyring JSON/)
			try {
				createAesGcmKeyringFromJson(input)
			} catch (error) {
				expect(String(error)).not.toContain('secret-value')
			}
		}
	})

	it('rejects duplicate and unconfigured keyring keys', async () => {
		const key = randomHex(32)
		expect(() => createAesGcmKeyring({ activeKeyId: 'missing', keys: { current: key } })).toThrow(
			/active AES-GCM key ID/
		)
		expect(() => createAesGcmKeyring({ activeKeyId: 'a', keys: { a: key, b: key } })).toThrow(
			/must be distinct/
		)

		const keyring = createAesGcmKeyring({ activeKeyId: 'current', keys: { current: key } })
		await expect(
			openAesGcmWithKeyring({
				keyring,
				sealed: {
					keyId: 'retired',
					seal: { algorithm: 'AES-GCM', iv: 'invalid', ciphertext: 'invalid' }
				}
			})
		).rejects.toThrow(/not configured/)
	})
})
