import { describe, expect, it } from 'vitest'

import {
	createRateLimiter,
	D1RateLimitStore,
	MemoryRateLimitStore
} from '../src/rate-limit/index.js'

type FakeRateLimitRow = {
	count: number | string | null
	reset_at: number | string | null
}

class FakeD1RateLimitDatabase {
	readonly rows = new Map<string, FakeRateLimitRow>()

	prepare(sql: string) {
		return {
			bind: (...args: Array<string | number | boolean | null>) => ({
				first: async <T = FakeRateLimitRow>() => {
					const key = String(args[0])
					return (this.rows.get(key) ?? null) as T | null
				},
				run: async () => {
					const key = String(args[0])
					if (/^INSERT/i.test(sql.trim())) {
						this.rows.set(key, {
							count: args[1] as string,
							reset_at: args[2] as number
						})
					}
					if (/^DELETE/i.test(sql.trim())) {
						this.rows.delete(key)
					}
				}
			})
		}
	}
}

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

	it('supports D1-backed sliding-window limits', async () => {
		const db = new FakeD1RateLimitDatabase()
		const limiter = createRateLimiter({
			windows: [ { name: 'burst', windowMs: 60_000, maxEvents: 2 } ],
			store: new D1RateLimitStore(db),
			keyPrefix: 'auth'
		})

		expect((await limiter.check('alice')).allowed).toBe(true)
		expect((await limiter.check('alice')).allowed).toBe(true)
		expect((await limiter.check('alice')).allowed).toBe(false)
		expect(db.rows.get('auth:alice')?.count).toMatch(/^\[/)
	})

	it('reads legacy D1 numeric count rows', async () => {
		const db = new FakeD1RateLimitDatabase()
		db.rows.set('auth:alice', {
			count: 2,
			reset_at: Math.ceil((Date.now() + 60_000) / 1000)
		})
		const store = new D1RateLimitStore(db)

		const entry = await store.incrementEntry('auth:alice', Date.now(), 60_000, 4)

		expect(entry.timestamps).toHaveLength(3)
		expect(db.rows.get('auth:alice')?.count).toMatch(/^\[/)
	})
})
