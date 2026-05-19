import { describe, expect, it } from 'vitest'

import { createRateLimiter, MemoryRateLimitStore } from '../src/rate-limit/index.js'

describe('createRateLimiter', () => {
	it('throws on empty windows', () => {
		expect(() => createRateLimiter({ windows: [] })).toThrowError(/at least one window/)
	})

	it('allows requests within the limit', async () => {
		const limiter = createRateLimiter({
			windows: [ { name: 'burst', windowMs: 60_000, maxEvents: 3 } ]
		})

		expect((await limiter.check('alice')).allowed).toBe(true)
		expect((await limiter.check('alice')).allowed).toBe(true)
		expect((await limiter.check('alice')).allowed).toBe(true)
	})

	it('blocks the request that exceeds the limit', async () => {
		const limiter = createRateLimiter({
			windows: [ { name: 'burst', windowMs: 60_000, maxEvents: 2 } ]
		})

		await limiter.check('alice')
		await limiter.check('alice')
		const verdict = await limiter.check('alice')

		expect(verdict.allowed).toBe(false)
		if (!verdict.allowed) {
			expect(verdict.window).toBe('burst')
			expect(verdict.retryAfterSec).toBeGreaterThan(0)
		}
	})

	it('isolates identifiers', async () => {
		const limiter = createRateLimiter({
			windows: [ { name: 'burst', windowMs: 60_000, maxEvents: 1 } ]
		})

		expect((await limiter.check('alice')).allowed).toBe(true)
		expect((await limiter.check('bob')).allowed).toBe(true)
		expect((await limiter.check('alice')).allowed).toBe(false)
		expect((await limiter.check('bob')).allowed).toBe(false)
	})

	it('respects multiple windows (tightest wins)', async () => {
		const limiter = createRateLimiter({
			windows: [
				{ name: 'burst', windowMs: 60_000, maxEvents: 10 },
				{ name: 'hour', windowMs: 3_600_000, maxEvents: 2 }
			]
		})

		await limiter.check('alice')
		await limiter.check('alice')
		const verdict = await limiter.check('alice')

		expect(verdict.allowed).toBe(false)
		if (!verdict.allowed) expect(verdict.window).toBe('hour')
	})

	it('reset clears the identifier', async () => {
		const limiter = createRateLimiter({
			windows: [ { name: 'burst', windowMs: 60_000, maxEvents: 1 } ]
		})
		await limiter.check('alice')
		expect((await limiter.check('alice')).allowed).toBe(false)
		await limiter.reset('alice')
		expect((await limiter.check('alice')).allowed).toBe(true)
	})

	it('exposes remaining when allowed', async () => {
		const limiter = createRateLimiter({
			windows: [ { name: 'burst', windowMs: 60_000, maxEvents: 3 } ]
		})
		const v = await limiter.check('alice')
		expect(v.allowed).toBe(true)
		if (v.allowed) expect(v.remaining).toBe(2)
	})

	it('respects keyPrefix isolation', async () => {
		const store = new MemoryRateLimitStore()
		const a = createRateLimiter({
			windows: [ { name: 'burst', windowMs: 60_000, maxEvents: 1 } ],
			store,
			keyPrefix: 'a'
		})
		const b = createRateLimiter({
			windows: [ { name: 'burst', windowMs: 60_000, maxEvents: 1 } ],
			store,
			keyPrefix: 'b'
		})

		await a.check('alice')
		expect((await a.check('alice')).allowed).toBe(false)
		expect((await b.check('alice')).allowed).toBe(true)
	})

	it('bounds per-identifier timestamp storage to maxEvents + 1', async () => {
		const store = new MemoryRateLimitStore({ cleanupProbability: 0 })
		const limiter = createRateLimiter({
			windows: [ { name: 'burst', windowMs: 60_000, maxEvents: 2 } ],
			store
		})

		for (let i = 0; i < 100; i++) {
			await limiter.check('alice')
		}

		const entry = store.getEntry('rate-limit:alice')
		expect(entry?.timestamps).toHaveLength(3)
	})
})
