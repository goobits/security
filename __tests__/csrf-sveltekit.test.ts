import type { Cookies, RequestEvent } from '@sveltejs/kit'
import { describe, expect, it, vi } from 'vitest'

import {
	createSvelteKitCsrf,
	type SvelteKitCsrfConfig
} from '../src/csrf/sveltekit.js'

const SECRET = 'csrf-test-secret-that-is-at-least-32-bytes'
const SESSION_BINDING = 'session-123'

function event(request: Request, initialCookies: Record<string, string> = {}): RequestEvent {
	const values = new Map(Object.entries(initialCookies))
	const cookies = {
		get: (name: string) => values.get(name),
		set: vi.fn((name: string, value: string) => values.set(name, value))
	} as unknown as Cookies

	return {
		request,
		url: new URL(request.url),
		locals: {},
		cookies,
		platform: undefined,
		getClientAddress: () => '127.0.0.1'
	} as unknown as RequestEvent
}

function request(body?: BodyInit, headers: Record<string, string> = {}): Request {
	return new Request('https://example.test/contact', {
		method: body === undefined ? 'GET' : 'POST',
		headers,
		body
	})
}

function sessionCsrf(overrides: Partial<SvelteKitCsrfConfig> = {}) {
	return createSvelteKitCsrf({
		secret: SECRET,
		cookieName: 'csrf_token',
		getSessionBinding: () => SESSION_BINDING,
		...overrides
	})
}

describe('createSvelteKitCsrf', () => {
	it('binds anonymous tokens to an HttpOnly __Host- cookie in secure deployments', async () => {
		const csrf = createSvelteKitCsrf({
			secret: SECRET,
			cookieName: 'csrf_token',
			cookieOptions: { httpOnly: true, sameSite: 'strict', secure: true, path: '/', maxAge: 60 }
		})
		const requestEvent = event(request())

		const token = await csrf.generate(requestEvent)

		expect(token).toMatch(/^v1\.[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}$/u)
		expect(csrf.bindingCookieName).toBe('__Host-csrf_token-binding')
		expect(csrf.protection.storeSize).toBe(0)
		expect(requestEvent.cookies.set).toHaveBeenNthCalledWith(
			1,
			'__Host-csrf_token-binding',
			expect.stringMatching(/^[A-Za-z0-9_-]{43}$/u),
			{ httpOnly: true, sameSite: 'lax', secure: true, path: '/', maxAge: 60 }
		)
		expect(requestEvent.cookies.set).toHaveBeenNthCalledWith(2, 'csrf_token', token, {
			httpOnly: true,
			sameSite: 'strict',
			secure: true,
			path: '/',
			maxAge: 60
		})
	})

	it('reuses a token only while its session binding remains valid', async () => {
		const csrf = createSvelteKitCsrf({
			secret: SECRET,
			cookieName: 'csrf_token',
			getSessionBinding: (requestEvent) =>
				(requestEvent.locals as { sessionId?: string }).sessionId ?? null
		})
		const requestEvent = event(request())
		;(requestEvent.locals as { sessionId?: string }).sessionId = 'session-1'
		const first = await csrf.generate(requestEvent)
		vi.mocked(requestEvent.cookies.set).mockClear()

		await expect(csrf.getOrCreate(requestEvent)).resolves.toBe(first)
		expect(requestEvent.cookies.set).not.toHaveBeenCalled()

		;(requestEvent.locals as { sessionId?: string }).sessionId = 'session-2'
		const second = await csrf.getOrCreate(requestEvent)
		expect(second).not.toBe(first)
		expect(requestEvent.cookies.set).toHaveBeenCalledTimes(1)
	})

	it('supports thin package bridges with an explicit binding', async () => {
		const csrf = sessionCsrf()
		const requestEvent = event(request())
		const token = await csrf.issue(requestEvent.cookies, {
			sessionBinding: SESSION_BINDING,
			trackExpiry: false
		})
		const candidate = request(undefined, { 'X-CSRF-Token': token })

		await expect(
			csrf.validateRequest(candidate, requestEvent.cookies, {
				sessionBinding: SESSION_BINDING
			})
		).resolves.toBe(true)
	})

	it('validates header, URL-encoded, JSON, and multipart tokens', async () => {
		const csrf = sessionCsrf()
		const seed = event(request())
		const token = await csrf.generate(seed)
		const cases = [
			request(undefined, { 'X-CSRF-Token': token }),
			request(`csrf_token=${token}`, { 'Content-Type': 'application/x-www-form-urlencoded' }),
			request(JSON.stringify({ csrf_token: token }), { 'Content-Type': 'application/json' }),
			request(
				(() => {
					const form = new FormData()
					form.set('csrf_token', token)
					return form
				})()
			)
		]

		for (const candidate of cases) {
			await expect(csrf.validate(event(candidate, { csrf_token: token }))).resolves.toBe(true)
		}
	})

	it('rejects missing, mismatched, malformed, oversized, and unbound tokens', async () => {
		const csrf = sessionCsrf({ maxBodyBytes: 32 })
		const seed = event(request())
		const token = await csrf.generate(seed)
		const cases = [
			event(request(''), { csrf_token: token }),
			event(request(undefined, { 'X-CSRF-Token': 'wrong' }), { csrf_token: token }),
			event(request('{', { 'Content-Type': 'application/json' }), { csrf_token: token }),
			event(
				request(`csrf_token=${token}`, { 'Content-Type': 'application/x-www-form-urlencoded' }),
				{ csrf_token: token }
			)
		]

		for (const candidate of cases) {
			await expect(csrf.validate(candidate)).resolves.toBe(false)
		}

		const anonymous = createSvelteKitCsrf({ secret: SECRET, cookieName: 'csrf_token' })
		await expect(
			anonymous.validate(event(request(undefined, { 'X-CSRF-Token': token }), { csrf_token: token }))
		).resolves.toBe(false)
	})

	it('allows safe methods and rejects unsafe requests through its handle', async () => {
		const csrf = createSvelteKitCsrf({ secret: SECRET, cookieName: 'csrf_token' })
		const resolve = vi.fn().mockResolvedValue(new Response('OK'))

		const allowed = await csrf.handle({ event: event(request()), resolve })
		const denied = await csrf.handle({ event: event(request('missing-token')), resolve })

		expect(await allowed.text()).toBe('OK')
		expect(denied.status).toBe(403)
		expect(resolve).toHaveBeenCalledTimes(1)
	})

	it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])(
		'rejects invalid maxBodyBytes %s',
		(maxBodyBytes) => {
			expect(() => createSvelteKitCsrf({ secret: SECRET, maxBodyBytes })).toThrowError(
				/positive safe integer/
			)
		}
	)
})
