import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { verifyTurnstile } from '../src/turnstile.js'

const originalFetch = globalThis.fetch
const originalProcessEnv = globalThis.process?.env

function mockFetch(response: { ok?: boolean; status?: number; body: object }): void {
	globalThis.fetch = vi.fn(async () => ({
		ok: response.ok ?? true,
		status: response.status ?? 200,
		json: async () => response.body
	}) as unknown as Response) as typeof fetch
}

beforeEach(() => {
	if (globalThis.process?.env) {
		delete globalThis.process.env['NODE_ENV']
		delete globalThis.process.env['TURNSTILE_SECRET_KEY']
	}
})

afterEach(() => {
	globalThis.fetch = originalFetch
	if (globalThis.process?.env && originalProcessEnv) {
		globalThis.process.env['NODE_ENV'] = originalProcessEnv['NODE_ENV']
		globalThis.process.env['TURNSTILE_SECRET_KEY'] = originalProcessEnv['TURNSTILE_SECRET_KEY']
	}
	vi.restoreAllMocks()
})

describe('verifyTurnstile', () => {
	it('returns missing-token when no token is provided', async() => {
		const result = await verifyTurnstile(null, { secretKey: 'sk' })
		expect(result.success).toBe(false)
		if (!result.success) expect(result.reason).toBe('missing-token')
	})

	it('returns missing-secret when no secretKey and no env var', async() => {
		const result = await verifyTurnstile('token', {})
		expect(result.success).toBe(false)
		if (!result.success) expect(result.reason).toBe('missing-secret')
	})

	it('does NOT silently bypass on Workers-like env (no NODE_ENV) without opt-in', async() => {
		const result = await verifyTurnstile('token', {})
		expect(result.success).toBe(false)
	})

	it('permits dev bypass only when explicitly opted in AND NODE_ENV !== production', async() => {
		if (globalThis.process?.env) globalThis.process.env['NODE_ENV'] = 'development'
		const result = await verifyTurnstile('token', { allowInDevelopment: true })
		expect(result.success).toBe(true)
	})

	it('ignores the dev bypass in production even when opt-in is set', async() => {
		if (globalThis.process?.env) globalThis.process.env['NODE_ENV'] = 'production'
		const result = await verifyTurnstile('token', { allowInDevelopment: true })
		expect(result.success).toBe(false)
	})

	it('reads TURNSTILE_SECRET_KEY from env when option omitted', async() => {
		if (globalThis.process?.env) globalThis.process.env['TURNSTILE_SECRET_KEY'] = 'env-secret'
		mockFetch({ body: { success: true, hostname: 'example.com' } })

		const result = await verifyTurnstile('token', {})
		expect(result.success).toBe(true)
		expect(globalThis.fetch).toHaveBeenCalledOnce()
	})

	it('returns success result with action and hostname from the API response', async() => {
		mockFetch({ body: { success: true, action: 'contact', hostname: 'example.com' } })

		const result = await verifyTurnstile('token', { secretKey: 'sk' })
		expect(result.success).toBe(true)
		if (result.success) {
			expect(result.action).toBe('contact')
			expect(result.hostname).toBe('example.com')
		}
	})

	it('returns verification-failed when API reports success: false', async() => {
		mockFetch({ body: { success: false, 'error-codes': [ 'invalid-input-response' ] } })

		const result = await verifyTurnstile('token', { secretKey: 'sk' })
		expect(result.success).toBe(false)
		if (!result.success) {
			expect(result.reason).toBe('verification-failed')
			expect(result.errorCodes).toEqual([ 'invalid-input-response' ])
		}
	})

	it('returns action-mismatch when expected action does not match', async() => {
		mockFetch({ body: { success: true, action: 'wrong' } })

		const result = await verifyTurnstile('token', { secretKey: 'sk', action: 'contact' })
		expect(result.success).toBe(false)
		if (!result.success) expect(result.reason).toBe('action-mismatch')
	})

	it('returns hostname-mismatch when expected hostname does not match', async() => {
		mockFetch({ body: { success: true, hostname: 'evil.example' } })

		const result = await verifyTurnstile('token', { secretKey: 'sk', hostname: 'example.com' })
		expect(result.success).toBe(false)
		if (!result.success) expect(result.reason).toBe('hostname-mismatch')
	})

	it('returns api-error when the fetch responds non-2xx', async() => {
		mockFetch({ ok: false, status: 502, body: {} })

		const result = await verifyTurnstile('token', { secretKey: 'sk' })
		expect(result.success).toBe(false)
		if (!result.success) {
			expect(result.reason).toBe('api-error')
			expect(result.statusCode).toBe(502)
		}
	})

	it('returns api-error when fetch rejects', async() => {
		globalThis.fetch = vi.fn(async () => {
			throw new Error('network down')
		}) as typeof fetch

		const result = await verifyTurnstile('token', { secretKey: 'sk' })
		expect(result.success).toBe(false)
		if (!result.success) expect(result.reason).toBe('api-error')
	})

	it('forwards remoteIp to the siteverify body when provided', async() => {
		const fetchMock = vi.fn(async () => ({
			ok: true,
			status: 200,
			json: async () => ({ success: true })
		}) as unknown as Response)
		globalThis.fetch = fetchMock as typeof fetch

		await verifyTurnstile('token', { secretKey: 'sk', remoteIp: '203.0.113.5' })

		const calls = fetchMock.mock.calls as unknown as [ string, RequestInit ][]
		expect(calls.length).toBe(1)
		const body = calls[0]?.[1]?.body as URLSearchParams
		expect(body.get('remoteip')).toBe('203.0.113.5')
		expect(body.get('secret')).toBe('sk')
		expect(body.get('response')).toBe('token')
	})

	it('skips siteverify entirely when bypassLocalhost matches remoteIp (non-prod)', async() => {
		const fetchSpy = vi.fn()
		globalThis.fetch = fetchSpy as unknown as typeof fetch

		const result = await verifyTurnstile('token', {
			secretKey: 'sk',
			remoteIp: '127.0.0.1',
			bypassLocalhost: true
		})

		expect(result.success).toBe(true)
		expect(fetchSpy).not.toHaveBeenCalled()
	})

	it('still calls siteverify when bypassLocalhost is set but remoteIp is NOT loopback', async() => {
		mockFetch({ body: { success: true } })

		await verifyTurnstile('token', {
			secretKey: 'sk',
			remoteIp: '203.0.113.5',
			bypassLocalhost: true
		})

		expect(globalThis.fetch).toHaveBeenCalledOnce()
	})

	it('ignores bypassLocalhost in production', async() => {
		if (globalThis.process?.env) globalThis.process.env['NODE_ENV'] = 'production'
		mockFetch({ body: { success: true } })

		await verifyTurnstile('token', {
			secretKey: 'sk',
			remoteIp: '127.0.0.1',
			bypassLocalhost: true
		})

		expect(globalThis.fetch).toHaveBeenCalledOnce()
	})

	it('honors custom bypassHosts list', async() => {
		const fetchSpy = vi.fn()
		globalThis.fetch = fetchSpy as unknown as typeof fetch

		const result = await verifyTurnstile('token', {
			secretKey: 'sk',
			remoteIp: '10.0.0.5',
			bypassLocalhost: true,
			bypassHosts: [ '10.0.0.5' ]
		})

		expect(result.success).toBe(true)
		expect(fetchSpy).not.toHaveBeenCalled()
	})
})
