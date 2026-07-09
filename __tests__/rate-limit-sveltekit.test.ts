import type { RequestEvent } from '@sveltejs/kit'
import { describe, expect, it, vi } from 'vitest'

import { createRateLimitHandle } from '../src/rate-limit/sveltekit.js'
import type { RateLimiter } from '../src/rate-limit/index.js'

function event(path = '/api'): RequestEvent {
	const request = new Request(`https://pdx.fun${path}`)
	return {
		request,
		url: new URL(request.url),
		locals: {},
		cookies: {},
		platform: undefined,
		getClientAddress: () => '127.0.0.1'
	} as unknown as RequestEvent
}

function limiter(verdict: Awaited<ReturnType<RateLimiter['check']>>): RateLimiter {
	return {
		check: vi.fn().mockResolvedValue(verdict),
		peek: vi.fn().mockResolvedValue(verdict),
		reset: vi.fn(),
		config: { windows: [{ name: 'test', windowMs: 60_000, maxEvents: 1 }] }
	}
}

describe('createRateLimitHandle', () => {
	it('adds remaining and reset headers when a request is allowed', async () => {
		const rateLimiter = limiter({
			allowed: true,
			remaining: 4,
			resetAtMs: 1_700_000_000_000
		})
		const resolve = vi.fn().mockResolvedValue(new Response('OK'))
		const handle = createRateLimitHandle({
			limiter: rateLimiter,
			identifier: (requestEvent) => requestEvent.getClientAddress()
		})

		const response = await handle({ event: event('/allowed'), resolve })

		expect(response.status).toBe(200)
		expect(response.headers.get('X-RateLimit-Remaining')).toBe('4')
		expect(response.headers.get('X-RateLimit-Reset')).toBe('1700000000')
		expect(rateLimiter.check).toHaveBeenCalledWith('127.0.0.1')
	})

	it('skips limiter checks when the skip predicate matches', async () => {
		const rateLimiter = limiter({
			allowed: false,
			window: 'burst',
			retryAfterSec: 30,
			resetAtMs: Date.now() + 30_000
		})
		const resolve = vi.fn().mockResolvedValue(new Response('SKIPPED'))
		const handle = createRateLimitHandle({
			limiter: rateLimiter,
			identifier: () => 'ignored',
			skip: (requestEvent) => requestEvent.url.pathname === '/health'
		})

		const response = await handle({ event: event('/health'), resolve })

		expect(await response.text()).toBe('SKIPPED')
		expect(rateLimiter.check).not.toHaveBeenCalled()
	})

	it('returns the default 429 response and logs denied requests', async () => {
		const warn = vi.fn()
		const rateLimiter = limiter({
			allowed: false,
			window: 'burst',
			retryAfterSec: 45,
			resetAtMs: Date.now() + 45_000
		})
		const handle = createRateLimitHandle({
			limiter: rateLimiter,
			identifier: () => 'visitor-1',
			logger: { debug() {}, info() {}, warn, error() {} }
		})

		const response = await handle({
			event: event('/limited'),
			resolve: vi.fn().mockResolvedValue(new Response('unreached'))
		})

		expect(response.status).toBe(429)
		expect(response.headers.get('Retry-After')).toBe('45')
		await expect(response.json()).resolves.toEqual({
			error: 'Too many requests',
			retryAfter: 45,
			window: 'burst'
		})
		expect(warn).toHaveBeenCalledWith(
			'Rate-limited request',
			expect.objectContaining({
				path: '/limited',
				identifier: 'visitor-1',
				window: 'burst',
				retryAfterSec: 45
			})
		)
	})

	it('uses a custom response builder for denied requests', async () => {
		const rateLimiter = limiter({
			allowed: false,
			window: 'hour',
			retryAfterSec: 120,
			resetAtMs: Date.now() + 120_000
		})
		const handle = createRateLimitHandle({
			limiter: rateLimiter,
			identifier: () => 'visitor-2',
			buildResponse: (verdict) => new Response(`wait:${verdict.retryAfterSec}`, { status: 418 })
		})

		const response = await handle({
			event: event('/limited'),
			resolve: vi.fn().mockResolvedValue(new Response('unreached'))
		})

		expect(response.status).toBe(418)
		await expect(response.text()).resolves.toBe('wait:120')
	})
})
