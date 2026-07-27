import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { verifyRecaptcha } from '../src/recaptcha.js'

function mockFetch(response: { ok?: boolean; status?: number; body: object }): void {
	vi.stubGlobal(
		'fetch',
		vi.fn(
			async () =>
				({
					ok: response.ok ?? true,
					status: response.status ?? 200,
					json: async () => response.body
				}) as unknown as Response
		)
	)
}

beforeEach(() => {
	vi.stubEnv('NODE_ENV', '')
	vi.stubEnv('RECAPTCHA_SECRET_KEY', '')
})

afterEach(() => {
	vi.unstubAllGlobals()
	vi.unstubAllEnvs()
	vi.restoreAllMocks()
})

describe('verifyRecaptcha', () => {
	it('returns missing-token for empty token', async () => {
		const result = await verifyRecaptcha(null, { secretKey: 'sk' })
		expect(result.success).toBe(false)
		if (!result.success) expect(result.reason).toBe('missing-token')
	})

	it('returns missing-secret when no secretKey and no env var', async () => {
		const result = await verifyRecaptcha('token', {})
		expect(result.success).toBe(false)
		if (!result.success) expect(result.reason).toBe('missing-secret')
	})

	it('does NOT silently bypass on Workers-like env (no NODE_ENV)', async () => {
		// This is the critical security default: allowInDevelopment is false by default.
		const result = await verifyRecaptcha('token', {})
		expect(result.success).toBe(false)
	})

	it('does not bypass an unknown runtime even with explicit development opt-in', async () => {
		const result = await verifyRecaptcha('token', { allowInDevelopment: true })
		expect(result.success).toBe(false)
	})

	it('permits dev bypass only when explicitly opted in AND NODE_ENV !== production', async () => {
		vi.stubEnv('NODE_ENV', 'development')
		const result = await verifyRecaptcha('token', { allowInDevelopment: true })
		expect(result.success).toBe(true)
	})

	it('ignores the dev bypass in production even when opt-in is set', async () => {
		vi.stubEnv('NODE_ENV', 'production')
		const result = await verifyRecaptcha('token', { allowInDevelopment: true })
		expect(result.success).toBe(false)
	})

	it('returns success on Google success response (v2)', async () => {
		mockFetch({ body: { success: true } })
		const result = await verifyRecaptcha('token', { secretKey: 'sk' })
		expect(result.success).toBe(true)
	})

	it('returns api-error on non-OK status', async () => {
		mockFetch({ ok: false, status: 500, body: {} })
		const result = await verifyRecaptcha('token', { secretKey: 'sk' })
		expect(result.success).toBe(false)
		if (!result.success) {
			expect(result.reason).toBe('api-error')
			expect(result.statusCode).toBe(500)
		}
	})

	it('returns api-error when the API response is not valid JSON', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn(
				async () =>
					({
						ok: true,
						status: 200,
						json: async () => {
							throw new SyntaxError('not json')
						}
					}) as unknown as Response
			)
		)

		const result = await verifyRecaptcha('token', { secretKey: 'sk' })
		expect(result.success).toBe(false)
		if (!result.success) expect(result.reason).toBe('api-error')
	})

	it('returns api-error when the request times out', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn(
				(_url, init) =>
					new Promise<Response>((_resolve, reject) => {
						const signal = (init as RequestInit | undefined)?.signal
						signal?.addEventListener('abort', () => {
							reject(new DOMException('Aborted', 'AbortError'))
						})
					})
			)
		)

		const result = await verifyRecaptcha('token', { secretKey: 'sk', timeoutMs: 1 })
		expect(result.success).toBe(false)
		if (!result.success) expect(result.reason).toBe('api-error')
	})

	it('returns verification-failed on Google success=false', async () => {
		mockFetch({ body: { success: false, 'error-codes': ['invalid-input-response'] } })
		const result = await verifyRecaptcha('token', { secretKey: 'sk' })
		expect(result.success).toBe(false)
		if (!result.success) {
			expect(result.reason).toBe('verification-failed')
			expect(result.errorCodes).toEqual(['invalid-input-response'])
		}
	})

	it('returns score-too-low when v3 score is below minScore', async () => {
		mockFetch({ body: { success: true, score: 0.3, action: 'submit' } })
		const result = await verifyRecaptcha('token', { secretKey: 'sk', minScore: 0.7 })
		expect(result.success).toBe(false)
		if (!result.success) {
			expect(result.reason).toBe('score-too-low')
			expect(result.score).toBe(0.3)
		}
	})

	it('returns action-mismatch when v3 action differs', async () => {
		mockFetch({ body: { success: true, score: 0.9, action: 'login' } })
		const result = await verifyRecaptcha('token', {
			secretKey: 'sk',
			action: 'submit',
			minScore: 0.5
		})
		expect(result.success).toBe(false)
		if (!result.success) expect(result.reason).toBe('action-mismatch')
	})

	it('returns success when v3 score and action both pass', async () => {
		mockFetch({ body: { success: true, score: 0.9, action: 'submit' } })
		const result = await verifyRecaptcha('token', {
			secretKey: 'sk',
			action: 'submit',
			minScore: 0.5
		})
		expect(result.success).toBe(true)
		if (result.success) {
			expect(result.score).toBe(0.9)
			expect(result.action).toBe('submit')
		}
	})
})
