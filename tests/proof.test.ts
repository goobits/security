import { describe, expect, it } from 'vitest'

import {
	attachSecurityProof,
	canonicalizeJson,
	createSecurityProof,
	verifyAttachedSecurityProof,
	verifySecurityProof
} from '../src/crypto/index.js'

const SECRET = 'test-secret-not-for-production-use-min-32-chars-long'

describe('canonicalizeJson', () => {
	it('sorts object keys recursively', () => {
		expect(canonicalizeJson({ b: 2, a: { d: 4, c: 3 } })).toBe('{"a":{"c":3,"d":4},"b":2}')
	})
})

describe('security proofs', () => {
	it('creates and verifies detached proofs', async () => {
		const payload = { id: 'msg-1', value: 42 }
		const proof = await createSecurityProof(payload, {
			secret: SECRET,
			verificationMethod: 'hmac:test',
			domain: 'example.test',
			challenge: 'nonce-1'
		})

		const result = await verifySecurityProof(payload, proof, {
			secret: SECRET,
			verificationMethod: 'hmac:test',
			domain: 'example.test',
			challenge: 'nonce-1'
		})

		expect(result).toEqual({ ok: true })
	})

	it('rejects tampered payloads', async () => {
		const proof = await createSecurityProof({ id: 'msg-1' }, {
			secret: SECRET,
			verificationMethod: 'hmac:test'
		})

		const result = await verifySecurityProof({ id: 'msg-2' }, proof, { secret: SECRET })
		expect(result).toEqual({ ok: false, reason: 'invalid-signature' })
	})

	it('checks domain and challenge before signature verification', async () => {
		const proof = await createSecurityProof({ id: 'msg-1' }, {
			secret: SECRET,
			verificationMethod: 'hmac:test',
			domain: 'example.test',
			challenge: 'nonce-1'
		})

		await expect(verifySecurityProof({ id: 'msg-1' }, proof, {
			secret: SECRET,
			domain: 'other.test'
		})).resolves.toEqual({ ok: false, reason: 'domain-mismatch' })
		await expect(verifySecurityProof({ id: 'msg-1' }, proof, {
			secret: SECRET,
			challenge: 'nonce-2'
		})).resolves.toEqual({ ok: false, reason: 'challenge-mismatch' })
	})

	it('rejects old proofs when maxAgeMs is set', async () => {
		const proof = await createSecurityProof({ id: 'msg-1' }, {
			secret: SECRET,
			verificationMethod: 'hmac:test',
			created: '2026-06-13T00:00:00.000Z'
		})

		const result = await verifySecurityProof({ id: 'msg-1' }, proof, {
			secret: SECRET,
			now: new Date('2026-06-13T00:01:01.000Z'),
			maxAgeMs: 60_000
		})

		expect(result).toEqual({ ok: false, reason: 'expired' })
	})

	it('attaches and verifies proofs without signing the proof field itself', async () => {
		const signed = await attachSecurityProof({ id: 'msg-1' }, {
			secret: SECRET,
			verificationMethod: 'hmac:test'
		})

		expect(signed.proof.type).toBe('SecurityProof')
		await expect(verifyAttachedSecurityProof(signed, { secret: SECRET })).resolves.toEqual({ ok: true })
		await expect(verifyAttachedSecurityProof({ ...signed, id: 'msg-2' }, { secret: SECRET }))
			.resolves.toEqual({ ok: false, reason: 'invalid-signature' })
	})
})
