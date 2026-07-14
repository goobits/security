import { describe, expect, it } from 'vitest'

import {
	base64UrlToBytes,
	bytesToBase64Url,
	bytesToHex,
	bytesToText,
	constantTimeEqual,
	hexToBytes,
	openAesGcm,
	openJson,
	randomBytes,
	randomHex,
	sealAesGcm,
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
})
