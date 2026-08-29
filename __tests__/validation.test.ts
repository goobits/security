import { describe, expect, it, vi } from 'vitest'
import { z } from 'zod'

import { getInputValidator } from '../src/validation.js'
import { readAsyncIterableBytes } from '../src/requestBody.js'
import {
	BodyTooLargeError,
	readRequestBodyBytes,
	withValidation
} from '../src/validation/sveltekit.js'

describe('getInputValidator', () => {
	const schema = z.object({
		email: z.email(),
		name: z.string().min(1)
	})

	it('returns success + data on valid input', () => {
		const validate = getInputValidator(schema)
		const result = validate({ email: 'a@b.com', name: 'Alice' })
		expect(result.success).toBe(true)
		if (result.success) expect(result.data.email).toBe('a@b.com')
	})

	it('returns issues on invalid input', () => {
		const validate = getInputValidator(schema)
		const result = validate({ email: 'not-an-email', name: '' })
		expect(result.success).toBe(false)
		if (!result.success) {
			expect(result.issues.length).toBeGreaterThan(0)
			expect(result.issues.some((i) => i.path.includes('email'))).toBe(true)
			expect(result.issues.some((i) => i.path.includes('name'))).toBe(true)
		}
	})

	it('handles unknown input shape', () => {
		const validate = getInputValidator(schema)
		const result = validate('not an object')
		expect(result.success).toBe(false)
	})
})

describe('withValidation', () => {
	function makeEvent(body: unknown, headers: HeadersInit = {}, raw = false): { event: unknown } {
		const request = new Request('https://example.test/api?source=test', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', ...headers },
			body: raw ? String(body) : JSON.stringify(body)
		})
		return {
			event: {
				request,
				url: new URL('https://example.test/api?source=test'),
				params: {},
				locals: {},
				cookies: {},
				fetch: globalThis.fetch,
				getClientAddress: () => '127.0.0.1',
				platform: undefined,
				route: { id: null },
				setHeaders: () => {},
				isDataRequest: false,
				isSubRequest: false
			}
		}
	}

	it('adds validated data to SvelteKit locals', async () => {
		const handler = withValidation(
			{
				body: z.object({ email: z.email() }),
				query: z.object({ source: z.string() })
			},
			async (event) => new Response(event.locals.validatedData.body?.email ?? '')
		)

		const { event } = makeEvent({ email: 'a@b.com' })
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const response = await handler(event as any)

		expect(response.status).toBe(200)
		expect(await response.text()).toBe('a@b.com')
	})

	it('rejects oversized request bodies before JSON parsing', async () => {
		const handler = withValidation(
			{ body: z.object({ email: z.email() }) },
			async () => new Response('ok'),
			{ maxBodyBytes: 8 }
		)

		const { event } = makeEvent({ email: 'a@b.com' })
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const response = await handler(event as any)

		expect(response.status).toBe(413)
	})

	it('rejects malformed JSON as an invalid request body', async () => {
		const handler = withValidation({ body: z.object({ email: z.email() }) }, async () => {
			return new Response('should not run')
		})
		const { event } = makeEvent('not-json', { 'Content-Type': 'application/octet-stream' }, true)

		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const response = await handler(event as any)

		expect(response.status).toBe(400)
		expect(await response.json()).toMatchObject({
			success: false,
			error: 'Invalid request body'
		})
	})

	it('lets application handler errors propagate', async () => {
		const expected = new Error('handler failed')
		const handler = withValidation({ body: z.object({ email: z.email() }) }, async () => {
			throw expected
		})
		const { event } = makeEvent({ email: 'a@b.com' })

		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		await expect(handler(event as any)).rejects.toBe(expected)
	})
})

describe('readRequestBodyBytes', () => {
	it('reads mixed async byte and string chunks without Node-specific types', async () => {
		async function* body() {
			yield new Uint8Array([97])
			yield 'é'
		}

		const bytes = await readAsyncIterableBytes(body())
		expect(new TextDecoder().decode(bytes)).toBe('aé')
	})

	it('caps async iterable bodies by encoded byte length', async () => {
		async function* body() {
			yield 'éé'
		}

		await expect(readAsyncIterableBytes(body(), { maxBytes: 3 })).rejects.toBeInstanceOf(
			BodyTooLargeError
		)
	})

	it('caps streamed bodies without a content-length header', async () => {
		const request = new Request('https://example.test/upload', {
			method: 'POST',
			body: new ReadableStream({
				start(controller) {
					controller.enqueue(new Uint8Array(5))
					controller.enqueue(new Uint8Array(5))
					controller.close()
				}
			}),
			duplex: 'half'
		} as RequestInit)

		await expect(readRequestBodyBytes(request, { maxBytes: 8 })).rejects.toBeInstanceOf(
			BodyTooLargeError
		)
	})

	it('reports cancellation failures without hiding the body-size error', async() => {
		const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined)
		const cancellationError = new Error('cancel failed')
		const request = new Request('https://example.test/upload', {
			method: 'POST',
			body: new ReadableStream({
				cancel() {
					throw cancellationError
				},
				start(controller) {
					controller.enqueue(new Uint8Array(9))
				}
			}),
			duplex: 'half'
		} as RequestInit)

		await expect(readRequestBodyBytes(request, { maxBytes: 8 })).rejects.toBeInstanceOf(
			BodyTooLargeError
		)
		await vi.waitFor(() => {
			expect(consoleError).toHaveBeenCalledWith(
				expect.objectContaining({
					cause: cancellationError,
					message: 'Bounded request-body cancellation failed.'
				})
			)
		})
	})

	it('rejects invalid body limits at the configuration boundary', async () => {
		await expect(readAsyncIterableBytes([], { maxBytes: 0 })).rejects.toThrowError(
			/positive safe integer/
		)
	})
})
