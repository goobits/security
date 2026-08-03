import { describe, expect, it } from 'vitest'

import {
	BodyTooLargeError,
	readFormDataBody,
	readJsonBody,
	readRequestBodyBytes
} from '../src/requestBody.js'

describe('bounded request bodies', () => {
	it('parses bounded JSON and URL-encoded forms', async () => {
		await expect(
			readJsonBody(
				new Request('https://example.test/json', {
					method: 'POST',
					headers: { 'content-type': 'application/json' },
					body: JSON.stringify({ ok: true })
				})
			)
		).resolves.toEqual({ ok: true })

		const form = await readFormDataBody(
			new Request('https://example.test/form', {
				method: 'POST',
				headers: { 'content-type': 'application/x-www-form-urlencoded' },
				body: 'provider=apple&intent=link'
			})
		)
		expect(Object.fromEntries(form)).toEqual({ provider: 'apple', intent: 'link' })
	})

	it('parses bounded multipart forms without rereading the original stream', async () => {
		const source = new FormData()
		source.set('credentialId', 'passkey-1')
		const request = new Request('https://example.test/form', { method: 'POST', body: source })

		const form = await readFormDataBody(request, { maxBytes: 1_024 })

		expect(form.get('credentialId')).toBe('passkey-1')
		expect(request.bodyUsed).toBe(true)
	})

	it('rejects declared and streamed bodies above the configured limit', async () => {
		await expect(
			readRequestBodyBytes(
				new Request('https://example.test/form', {
					method: 'POST',
					headers: { 'content-length': '11' },
					body: 'small'
				}),
				{ maxBytes: 10 }
			)
		).rejects.toBeInstanceOf(BodyTooLargeError)

		await expect(
			readJsonBody(
				new Request('https://example.test/json', { method: 'POST', body: '12345678901' }),
				{ maxBytes: 10 }
			)
		).rejects.toBeInstanceOf(BodyTooLargeError)
	})
})
