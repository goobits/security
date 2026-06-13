import { describe, expect, it } from 'vitest'

import {
	buildDidWba,
	didWbaDomain,
	didWbaSignatureMessage,
	didWbaToUrl,
	parseDidWbaAuthorizationHeader,
	parseHttpSignatureHeader,
	verifyDidWbaIdentity,
	verifyHttpSignatureIdentity
} from '../src/identity/index.js'

describe('DID-WBA identity helpers', () => {
	it('builds and resolves DID-WBA identifiers', () => {
		const did = buildDidWba('example.com', [ 'agents', 'scout' ])

		expect(did).toBe('did:wba:example.com:agents:scout')
		expect(didWbaToUrl(did)).toBe('https://example.com/agents/scout/did.json')
		expect(didWbaDomain(did)).toBe('example.com')
	})

	it('parses DID-WBA authorization headers', () => {
		const parsed = parseDidWbaAuthorizationHeader(
			'DIDWba did="did:wba:example.com", nonce="n1", timestamp="2026-06-13T12:00:00.000Z", verification_method="did:wba:example.com#key-1", signature="sig"'
		)

		expect(parsed).toEqual({
			did: 'did:wba:example.com',
			nonce: 'n1',
			timestamp: '2026-06-13T12:00:00.000Z',
			verificationMethod: 'did:wba:example.com#key-1',
			signature: 'sig'
		})
	})

	it('verifies DID-WBA identity with caller-supplied signature verification', async () => {
		const header = {
			did: 'did:wba:example.com',
			nonce: 'n1',
			timestamp: '2026-06-13T12:00:00.000Z',
			verificationMethod: 'did:wba:example.com#key-1',
			signature: 'sig'
		}

		const result = await verifyDidWbaIdentity({
			header,
			expectedDomain: 'example.com',
			now: new Date('2026-06-13T12:00:30.000Z'),
			verifySignature: input =>
				input.message === didWbaSignatureMessage(header) && input.signature === 'sig'
		})

		expect(result.ok).toBe(true)
		if (result.ok) {
			expect(result.principal).toMatchObject({
				id: 'did:wba:example.com',
				method: 'did-wba'
			})
		}
	})

	it('rejects stale, wrong-domain, and bad-signature DID-WBA identities', async () => {
		const header = {
			did: 'did:wba:example.com',
			nonce: 'n1',
			timestamp: '2026-06-13T12:00:00.000Z',
			verificationMethod: 'did:wba:example.com#key-1',
			signature: 'sig'
		}

		await expect(verifyDidWbaIdentity({
			header,
			expectedDomain: 'other.example',
			verifySignature: () => true
		})).resolves.toEqual({ ok: false, reason: 'domain-mismatch' })
		await expect(verifyDidWbaIdentity({
			header,
			now: new Date('2026-06-13T12:02:00.000Z'),
			maxSkewMs: 60_000,
			verifySignature: () => true
		})).resolves.toEqual({ ok: false, reason: 'expired' })
		await expect(verifyDidWbaIdentity({
			header,
			now: new Date('2026-06-13T12:00:00.000Z'),
			verifySignature: () => false
		})).resolves.toEqual({ ok: false, reason: 'invalid-signature' })
	})
})

describe('HTTP signature identity helpers', () => {
	it('parses HTTP Signature headers', () => {
		expect(parseHttpSignatureHeader('keyId="did:wba:example.com#key-1",algorithm="ed25519",headers="date digest",signature="sig"'))
			.toEqual({
				keyId: 'did:wba:example.com#key-1',
				algorithm: 'ed25519',
				headers: [ 'date', 'digest' ],
				signature: 'sig'
			})
	})

	it('verifies HTTP Signature identity with caller-supplied verifier', async () => {
		const result = await verifyHttpSignatureIdentity({
			header: 'keyId="did:wba:example.com#key-1",signature="sig"',
			message: 'request-target: /',
			verifySignature: input => input.keyId === 'did:wba:example.com#key-1' && input.signature === 'sig'
		})

		expect(result.ok).toBe(true)
		if (result.ok) {
			expect(result.principal).toMatchObject({
				id: 'did:wba:example.com#key-1',
				method: 'http-signature'
			})
		}
	})
})
