import type { Cookies, RequestEvent } from '@sveltejs/kit'
import { describe, expect, it, vi } from 'vitest'

import { createSvelteKitCsrf } from '../src/csrf/sveltekit.js'

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

describe('createSvelteKitCsrf', () => {
	it('generates a stateless token and sets the configured SvelteKit cookie', async () => {
		const csrf = createSvelteKitCsrf({
			cookieName: 'csrf_token',
			cookieOptions: { httpOnly: true, sameSite: 'strict', secure: true, path: '/', maxAge: 60 }
		})
		const requestEvent = event(request())

		const token = await csrf.generate(requestEvent)

		expect(token).toMatch(/^[0-9a-f]{64}$/)
		expect(csrf.protection.storeSize).toBe(0)
		expect(requestEvent.cookies.set).toHaveBeenCalledWith('csrf_token', token, {
			httpOnly: true,
			sameSite: 'strict',
			secure: true,
			path: '/',
			maxAge: 60
		})
	})

	it('reuses an existing cookie token', async () => {
		const csrf = createSvelteKitCsrf({ cookieName: 'csrf_token' })
		const requestEvent = event(request(), { csrf_token: 'existing' })

		await expect(csrf.getOrCreate(requestEvent)).resolves.toBe('existing')
		expect(requestEvent.cookies.set).not.toHaveBeenCalled()
	})

	it('supports thin package bridges without reconstructing request events', async () => {
		const token = 'a'.repeat(64)
		const requestEvent = event(request(), { csrf_token: token })
		const csrf = createSvelteKitCsrf({ cookieName: 'csrf_token' })
		const candidate = request(undefined, { 'X-CSRF-Token': token })

		await expect(csrf.validateRequest(candidate, requestEvent.cookies)).resolves.toBe(true)
		await expect(csrf.issue(requestEvent.cookies)).resolves.toMatch(/^[0-9a-f]{64}$/)
	})

	it('validates header, URL-encoded, JSON, and multipart tokens', async () => {
		const token = 'a'.repeat(64)
		const csrf = createSvelteKitCsrf({ cookieName: 'csrf_token' })
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

	it('rejects missing, mismatched, malformed, and oversized tokens', async () => {
		const token = 'a'.repeat(64)
		const csrf = createSvelteKitCsrf({ cookieName: 'csrf_token', maxBodyBytes: 32 })
		const cases = [
			event(request(''), { csrf_token: token }),
			event(request(undefined, { 'X-CSRF-Token': 'wrong' }), { csrf_token: token }),
			event(request('{', { 'Content-Type': 'application/json' }), { csrf_token: token }),
			event(
				request(`csrf_token=${token}`, { 'Content-Type': 'application/x-www-form-urlencoded' }),
				{
					csrf_token: token
				}
			)
		]

		for (const candidate of cases) {
			await expect(csrf.validate(candidate)).resolves.toBe(false)
		}
	})

	it('allows safe methods and rejects unsafe requests through its handle', async () => {
		const csrf = createSvelteKitCsrf({ cookieName: 'csrf_token' })
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
			expect(() => createSvelteKitCsrf({ maxBodyBytes })).toThrowError(/positive safe integer/)
		}
	)
})
