import { describe, expect, it, vi } from 'vitest'

import {
	createHmacRateLimitStore,
	createRateLimiter,
	createResilientRateLimitStore,
	D1RateLimitStore,
	getClientIP,
	MemoryRateLimitStore,
	PostgresRateLimitStore,
	createPostgresRateLimitSchemaSql,
	postgresRateLimitSchemaSql,
	type RateLimitStore
} from '../src/rate-limit/index.js'

type FakeRateLimitRow = {
	count: number | string | null
	reset_at: number | string | null
}

class FakeD1RateLimitDatabase {
	readonly rows = new Map<string, FakeRateLimitRow>()
	selectCount = 0

	prepare(sql: string) {
		return {
			bind: (...args: Array<string | number | boolean | null>) => ({
				first: async <T = FakeRateLimitRow>() => {
					const key = String(args[0])
					if (/^INSERT/i.test(sql.trim())) {
						const timestamp = Number(args[1])
						const resetAt = Number(args[2])
						const retainedLimit = Number(args[5])
						const cutoff = Number(args[4])
						const current = this.rows.get(key)
						const currentResetAt = Number(current?.reset_at ?? 0) * 1000
						let timestamps: number[] = []
						if (current && currentResetAt > timestamp) {
							if (typeof current.count === 'string' && current.count.startsWith('[')) {
								timestamps = JSON.parse(current.count) as number[]
							}
						}
						timestamps = timestamps.filter((value) => value > cutoff)
						if (retainedLimit >= 0)
							timestamps = timestamps.slice(-retainedLimit || timestamps.length)
						timestamps.push(timestamp)
						this.rows.set(key, { count: JSON.stringify(timestamps), reset_at: resetAt })
						return this.rows.get(key) as T
					}
					this.selectCount++
					return (this.rows.get(key) ?? null) as T | null
				},
				run: async () => {
					const key = String(args[0])
					if (/^DELETE/i.test(sql.trim())) {
						this.rows.delete(key)
					}
				}
			})
		}
	}
}

class FakePostgresRateLimitDatabase {
	readonly rows = new Map<string, { timestamps: number[]; expires_at_ms: number }>()

	async query<T>(sql: string, params: readonly unknown[] = []): Promise<{ rows: T[] }> {
		const key = String(params[0])
		if (/^INSERT/i.test(sql.trim())) {
			const timestamp = Number(params[1])
			const ttlMs = Number(params[2])
			const cutoff = Number(params[3])
			const retainedLimit = params[4] === null ? undefined : Number(params[4])
			const current = this.rows.get(key)
			let timestamps =
				current && current.expires_at_ms > timestamp
					? current.timestamps.filter((value) => value > cutoff)
					: []
			if (retainedLimit !== undefined) {
				timestamps = retainedLimit === 0 ? [] : timestamps.slice(-retainedLimit)
			}
			timestamps.push(timestamp)
			const row = { timestamps, expires_at_ms: timestamp + ttlMs }
			this.rows.set(key, row)
			return { rows: [row as T] }
		}
		if (/^DELETE/i.test(sql.trim())) {
			this.rows.delete(key)
			return { rows: [] }
		}
		const row = this.rows.get(key)
		return { rows: row ? [row as T] : [] }
	}
}

describe('createResilientRateLimitStore', () => {
	const unavailableStore = (failure: Error): RateLimitStore => ({
		getEntry: () => Promise.reject(failure),
		incrementEntry: () => Promise.reject(failure),
		deleteEntry: () => Promise.reject(failure)
	})

	it('delegates every operation to the explicit fallback after primary failures', async () => {
		const failure = new Error('primary unavailable')
		const fallback = new MemoryRateLimitStore({ cleanupProbability: 0 })
		const onPrimaryError = vi.fn()
		const store = createResilientRateLimitStore({
			primary: unavailableStore(failure),
			failureMode: 'fallback',
			fallback,
			onPrimaryError
		})

		await expect(store.incrementEntry('alice', 1_000, 60_000, 3)).resolves.toEqual({
			timestamps: [1_000]
		})
		await expect(store.getEntry('alice')).resolves.toEqual({ timestamps: [1_000] })
		await expect(store.deleteEntry('alice')).resolves.toBeUndefined()
		await expect(store.getEntry('alice')).resolves.toBeNull()
		expect(onPrimaryError.mock.calls.map(([operation]) => operation)).toEqual([
			'incrementEntry',
			'getEntry',
			'deleteEntry',
			'getEntry'
		])
	})

	it('propagates the original failure in closed mode', async () => {
		const failure = new Error('primary unavailable')
		const store = createResilientRateLimitStore({
			primary: unavailableStore(failure),
			failureMode: 'closed'
		})

		await expect(store.getEntry('alice')).rejects.toBe(failure)
		await expect(store.incrementEntry('alice', 1_000, 60_000)).rejects.toBe(failure)
		await expect(store.deleteEntry('alice')).rejects.toBe(failure)
	})

	it('does not let a failing observer disable the fallback', async () => {
		const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined)
		const fallback = new MemoryRateLimitStore({ cleanupProbability: 0 })
		const store = createResilientRateLimitStore({
			primary: unavailableStore(new Error('primary unavailable')),
			failureMode: 'fallback',
			fallback,
			onPrimaryError: async () => {
				throw new Error('observer unavailable')
			}
		})

		await expect(store.incrementEntry('alice', 1_000, 60_000)).resolves.toEqual({
			timestamps: [1_000]
		})
		await vi.waitFor(() => {
			expect(consoleError).toHaveBeenCalledWith(
				expect.objectContaining({ message: 'Rate-limit primary-error observer failed.' })
			)
		})
	})

	it('clears the fallback after a successful primary delete', async () => {
		const primary = new MemoryRateLimitStore({ cleanupProbability: 0 })
		const fallback = new MemoryRateLimitStore({ cleanupProbability: 0 })
		fallback.incrementEntry('alice', 1_000, 60_000)
		const store = createResilientRateLimitStore({
			primary,
			failureMode: 'fallback',
			fallback
		})

		await store.deleteEntry('alice')
		expect(fallback.getEntry('alice')).toBeNull()
	})
})

describe('createRateLimiter', () => {
	it('throws on empty windows', () => {
		expect(() => createRateLimiter({ windows: [] })).toThrowError(/at least one window/)
	})

	it.each([
		['windowMs', 0],
		['windowMs', -1],
		['windowMs', Number.NaN],
		['windowMs', Number.POSITIVE_INFINITY],
		['windowMs', 1.5],
		['maxEvents', 0],
		['maxEvents', -1],
		['maxEvents', Number.NaN],
		['maxEvents', Number.POSITIVE_INFINITY],
		['maxEvents', 1.5]
	] as const)('rejects invalid %s values', (field, value) => {
		expect(() =>
			createRateLimiter({
				windows: [
					{
						name: 'invalid',
						windowMs: field === 'windowMs' ? value : 60_000,
						maxEvents: field === 'maxEvents' ? value : 10
					}
				]
			})
		).toThrow(`.${field} must be a positive safe integer`)
	})

	it('rejects empty window names', () => {
		expect(() =>
			createRateLimiter({ windows: [{ name: ' ', windowMs: 60_000, maxEvents: 10 }] })
		).toThrow('.name must not be empty')
	})

	it('allows requests within the limit', async () => {
		const limiter = createRateLimiter({
			windows: [{ name: 'burst', windowMs: 60_000, maxEvents: 3 }]
		})

		expect((await limiter.check('alice')).allowed).toBe(true)
		expect((await limiter.check('alice')).allowed).toBe(true)
		expect((await limiter.check('alice')).allowed).toBe(true)
	})

	it('blocks the request that exceeds the limit', async () => {
		const warn = vi.fn()
		const limiter = createRateLimiter({
			windows: [{ name: 'burst', windowMs: 60_000, maxEvents: 2 }],
			logger: { debug() {}, info() {}, warn, error() {} }
		})

		await limiter.check('alice')
		await limiter.check('alice')
		const verdict = await limiter.check('alice')

		expect(verdict.allowed).toBe(false)
		if (!verdict.allowed) {
			expect(verdict.window).toBe('burst')
			expect(verdict.retryAfterSec).toBeGreaterThan(0)
		}
		expect(warn).toHaveBeenCalledWith('Rate limit exceeded', {
			window: 'burst',
			event_count: 3,
			max_events: 2
		})
		expect(JSON.stringify(warn.mock.calls)).not.toContain('alice')
	})

	it('isolates identifiers', async () => {
		const limiter = createRateLimiter({
			windows: [{ name: 'burst', windowMs: 60_000, maxEvents: 1 }]
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
			windows: [{ name: 'burst', windowMs: 60_000, maxEvents: 1 }]
		})
		await limiter.check('alice')
		expect((await limiter.check('alice')).allowed).toBe(false)
		await limiter.reset('alice')
		expect((await limiter.check('alice')).allowed).toBe(true)
	})

	it('exposes remaining when allowed', async () => {
		const limiter = createRateLimiter({
			windows: [{ name: 'burst', windowMs: 60_000, maxEvents: 3 }]
		})
		const v = await limiter.check('alice')
		expect(v.allowed).toBe(true)
		if (v.allowed) expect(v.remaining).toBe(2)
	})

	it('respects keyPrefix isolation', async () => {
		const store = new MemoryRateLimitStore()
		const a = createRateLimiter({
			windows: [{ name: 'burst', windowMs: 60_000, maxEvents: 1 }],
			store,
			keyPrefix: 'a'
		})
		const b = createRateLimiter({
			windows: [{ name: 'burst', windowMs: 60_000, maxEvents: 1 }],
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
			windows: [{ name: 'burst', windowMs: 60_000, maxEvents: 2 }],
			store
		})

		for (let i = 0; i < 100; i++) {
			await limiter.check('alice')
		}

		const entry = store.getEntry('rate-limit:alice')
		expect(entry?.timestamps).toHaveLength(3)
	})

	it('bounds in-memory identifiers and retains recently incremented keys', () => {
		const store = new MemoryRateLimitStore({ cleanupProbability: 0, maxKeys: 2 })
		const now = Date.now()
		store.incrementEntry('oldest', now, 60_000)
		store.incrementEntry('newer', now, 60_000)
		store.incrementEntry('oldest', now + 1, 60_000)
		store.incrementEntry('newest', now + 2, 60_000)

		expect(store.size).toBe(2)
		expect(store.getEntry('oldest')).not.toBeNull()
		expect(store.getEntry('newer')).toBeNull()
		expect(store.getEntry('newest')).not.toBeNull()
	})

	it('cleans stale identifiers before evicting active ones at capacity', () => {
		const store = new MemoryRateLimitStore({ cleanupProbability: 0, maxKeys: 2 })
		const now = Date.now()
		store.incrementEntry('stale', 0, 60_000)
		store.incrementEntry('active', now, 60_000)
		store.incrementEntry('new', now, 60_000)

		expect(store.getEntry('stale')).toBeNull()
		expect(store.getEntry('active')).not.toBeNull()
		expect(store.getEntry('new')).not.toBeNull()
	})

	it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])(
		'rejects invalid in-memory maxKeys %s',
		(maxKeys) => {
			expect(() => new MemoryRateLimitStore({ maxKeys })).toThrowError(/positive safe integer/)
		}
	)

	it.each([-0.1, 1.1, Number.NaN, Number.POSITIVE_INFINITY])(
		'rejects invalid cleanup probability %s',
		(cleanupProbability) => {
			expect(() => new MemoryRateLimitStore({ cleanupProbability })).toThrowError(/between 0 and 1/)
		}
	)

	it('supports D1-backed sliding-window limits', async () => {
		const db = new FakeD1RateLimitDatabase()
		const limiter = createRateLimiter({
			windows: [{ name: 'burst', windowMs: 60_000, maxEvents: 2 }],
			store: new D1RateLimitStore(db),
			keyPrefix: 'auth'
		})

		expect((await limiter.check('alice')).allowed).toBe(true)
		expect((await limiter.check('alice')).allowed).toBe(true)
		expect((await limiter.check('alice')).allowed).toBe(false)
		expect(db.rows.get('auth:alice')?.count).toMatch(/^\[/)
		expect(db.selectCount).toBe(0)
	})

	it('shares bounded sliding-window limits through PostgreSQL', async () => {
		const db = new FakePostgresRateLimitDatabase()
		const first = createRateLimiter({
			windows: [{ name: 'burst', windowMs: 60_000, maxEvents: 2 }],
			store: new PostgresRateLimitStore(db),
			keyPrefix: 'auth'
		})
		const second = createRateLimiter({
			windows: [{ name: 'burst', windowMs: 60_000, maxEvents: 2 }],
			store: new PostgresRateLimitStore(db),
			keyPrefix: 'auth'
		})

		expect((await first.check('alice')).allowed).toBe(true)
		expect((await second.check('alice')).allowed).toBe(true)
		expect((await first.check('alice')).allowed).toBe(false)
		expect(db.rows.get('auth:alice')?.timestamps).toHaveLength(3)
	})

	it('rejects unsafe PostgreSQL rate-limit table identifiers', () => {
		const db = new FakePostgresRateLimitDatabase()

		expect(
			() => new PostgresRateLimitStore(db, { table: 'rate-limits; DROP TABLE users' })
		).toThrowError(/invalid SQL identifier/)
		expect(() =>
			createPostgresRateLimitSchemaSql({ table: 'rate-limits; DROP TABLE users' })
		).toThrowError(/invalid SQL identifier/)
	})

	it('shares one canonical PostgreSQL schema across default and custom tables', () => {
		expect(createPostgresRateLimitSchemaSql()).toBe(postgresRateLimitSchemaSql)
		expect(createPostgresRateLimitSchemaSql({ table: 'tenant_limits' })).toContain(
			'"tenant_limits_expires_at_idx"'
		)
	})

	it('atomically preserves concurrent D1 increments', async () => {
		const db = new FakeD1RateLimitDatabase()
		const store = new D1RateLimitStore(db)
		const now = Date.now()

		await Promise.all(
			Array.from({ length: 20 }, (_, index) =>
				store.incrementEntry('auth:alice', now + index, 60_000, 21)
			)
		)

		expect(JSON.parse(String(db.rows.get('auth:alice')?.count))).toHaveLength(20)
		expect(db.selectCount).toBe(0)
	})

	it('reads persisted D1 JSON timestamps and deletes obsolete numeric rows', async () => {
		const db = new FakeD1RateLimitDatabase()
		const store = new D1RateLimitStore(db)
		const now = Date.now()
		const resetAt = Math.ceil((now + 60_000) / 1000)
		const timestamps = [now - 2_000, now - 1_000]
		db.rows.set('json', { count: JSON.stringify(timestamps), reset_at: resetAt })
		db.rows.set('legacy', { count: 2, reset_at: resetAt })

		expect(await store.getEntry('json')).toEqual({ timestamps })
		expect(await store.getEntry('legacy')).toBeNull()
		expect(db.rows.has('legacy')).toBe(false)
	})

	it('deletes expired and malformed D1 rows instead of restoring bad counters', async () => {
		const db = new FakeD1RateLimitDatabase()
		const store = new D1RateLimitStore(db)
		const futureReset = Math.ceil((Date.now() + 60_000) / 1000)
		const invalidRows: Array<[string, FakeRateLimitRow]> = [
			['expired', { count: '[1]', reset_at: 0 }],
			['invalid-json', { count: '{', reset_at: futureReset }],
			['invalid-array', { count: '[1,"bad"]', reset_at: futureReset }],
			['zero-count', { count: 0, reset_at: futureReset }],
			['null-count', { count: null, reset_at: futureReset }],
			['invalid-reset', { count: 1, reset_at: 'not-a-number' }]
		]

		for (const [key, row] of invalidRows) db.rows.set(key, row)

		expect(await store.getEntry('missing')).toBeNull()
		for (const [key] of invalidRows) {
			expect(await store.getEntry(key)).toBeNull()
			expect(db.rows.has(key)).toBe(false)
		}
	})

	it('rejects unsafe D1 table identifiers', () => {
		const db = new FakeD1RateLimitDatabase()

		expect(() => new D1RateLimitStore(db, { table: 'rate-limits; DROP TABLE users' })).toThrowError(
			/invalid SQL identifier/
		)
	})

	it('fails loudly when a D1 increment returns no counter row', async () => {
		const db = {
			prepare() {
				return {
					bind() {
						return {
							async first<T>(): Promise<T | null> {
								return null
							},
							async run(): Promise<void> {}
						}
					}
				}
			}
		}
		const store = new D1RateLimitStore(db)

		await expect(store.incrementEntry('auth:alice', Date.now(), 60_000)).rejects.toThrowError(
			/increment did not return a valid entry/
		)
	})

	it('removes only stale in-memory entries during explicit cleanup', () => {
		const store = new MemoryRateLimitStore({ cleanupProbability: 0 })
		store.incrementEntry('expired', 0, 60_000)
		store.incrementEntry('active', Number.MAX_SAFE_INTEGER, 60_000)

		expect(store.cleanup(1)).toBe(1)
		expect(store.getEntry('expired')).toBeNull()
		expect(store.getEntry('active')).not.toBeNull()
	})

	it('runs configured opportunistic cleanup without dropping active entries', () => {
		const store = new MemoryRateLimitStore({ cleanupProbability: 1 })

		store.incrementEntry('active', Number.MAX_SAFE_INTEGER, 60_000)

		expect(store.size).toBe(1)
	})

	it('peeks at new and exhausted quotas without consuming another event', async () => {
		const store = new MemoryRateLimitStore({ cleanupProbability: 0 })
		const limiter = createRateLimiter({
			windows: [{ name: 'burst', windowMs: 60_000, maxEvents: 1 }],
			store
		})

		expect(await limiter.peek('alice')).toMatchObject({
			allowed: true,
			remaining: 1,
			window: 'burst'
		})
		await limiter.check('alice')
		await limiter.check('alice')
		const storedEvents = store.getEntry('rate-limit:alice')?.timestamps.length ?? 0

		expect(await limiter.peek('alice')).toMatchObject({
			allowed: false,
			window: 'burst'
		})
		expect(store.getEntry('rate-limit:alice')?.timestamps).toHaveLength(storedEvents)
	})

	it('pseudonymizes persisted keys with a dedicated HMAC secret', async () => {
		const primary = new MemoryRateLimitStore({ cleanupProbability: 0 })
		const store = createHmacRateLimitStore({
			store: primary,
			secret: 'rate-limit-secret-that-is-at-least-32-bytes',
			namespace: 'auth'
		})
		await store.incrementEntry('email:member@example.test', Date.now(), 60_000)

		expect(primary.size).toBe(1)
		expect(primary.getEntry('email:member@example.test')).toBeNull()
		expect(await store.getEntry('email:member@example.test')).not.toBeNull()
	})

	it('propagates backing-store failures instead of choosing availability policy', async () => {
		const failure = new Error('store unavailable')
		const store = createHmacRateLimitStore({
			secret: 'rate-limit-secret-that-is-at-least-32-bytes',
			store: {
				getEntry: async () => {
					throw failure
				},
				incrementEntry: async () => {
					throw failure
				},
				deleteEntry: async () => {
					throw failure
				}
			}
		})

		await expect(store.incrementEntry('alice', Date.now(), 60_000)).rejects.toBe(failure)
	})

	it('requires a dedicated high-entropy HMAC secret', () => {
		expect(() =>
			createHmacRateLimitStore({ store: new MemoryRateLimitStore(), secret: 'too-short' })
		).toThrow(/at least 32 bytes/)
	})
})

describe('getClientIP', () => {
	it('ignores spoofable proxy headers unless the caller explicitly trusts them', () => {
		const request = new Request('https://example.test', {
			headers: {
				'cf-connecting-ip': '203.0.113.1',
				'x-forwarded-for': '198.51.100.2, 10.0.0.1'
			}
		})

		expect(getClientIP(request)).toBe('unknown')
		expect(getClientIP(request, { trustHeaders: ['cf-connecting-ip'] })).toBe('203.0.113.1')
	})

	it('uses the first available trusted header and first forwarded address', () => {
		const request = new Request('https://example.test', {
			headers: { 'x-forwarded-for': ' 198.51.100.2, 10.0.0.1 ' }
		})

		expect(
			getClientIP(request, {
				trustHeaders: ['x-real-ip', 'x-forwarded-for']
			})
		).toBe('198.51.100.2')
	})

	it('resolves append-style forwarding chains from the trusted server side', () => {
		const request = new Request('https://example.test', {
			headers: {
				'x-forwarded-for': '198.51.100.1, 203.0.113.10, 192.0.2.50'
			}
		})

		expect(
			getClientIP(request, {
				trustHeaders: ['x-forwarded-for'],
				forwardedForTrustedProxyHops: 2
			})
		).toBe('203.0.113.10')
	})

	it('ignores spoofed left entries with one trusted append-style proxy', () => {
		const request = new Request('https://example.test', {
			headers: {
				'x-forwarded-for': '198.51.100.1, 203.0.113.10'
			}
		})

		expect(
			getClientIP(request, {
				trustHeaders: ['x-forwarded-for'],
				forwardedForTrustedProxyHops: 1
			})
		).toBe('203.0.113.10')
	})

	it('fails closed when the forwarding chain is shorter than the trusted hop count', () => {
		const request = new Request('https://example.test', {
			headers: { 'x-forwarded-for': '203.0.113.10' }
		})

		expect(
			getClientIP(request, {
				trustHeaders: ['x-forwarded-for'],
				forwardedForTrustedProxyHops: 2
			})
		).toBe('unknown')
	})

	it('rejects invalid trusted proxy hop counts', () => {
		const request = new Request('https://example.test')
		for (const forwardedForTrustedProxyHops of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
			expect(() =>
				getClientIP(request, {
					trustHeaders: ['x-forwarded-for'],
					forwardedForTrustedProxyHops
				})
			).toThrowError(/positive safe integer/)
		}
	})

	it('rejects a trusted forwarding chain with no first address', () => {
		const request = new Request('https://example.test', {
			headers: { 'x-forwarded-for': ', 198.51.100.2' }
		})

		expect(getClientIP(request, { trustHeaders: ['x-forwarded-for'] })).toBe('unknown')
	})

	it('rejects malformed or unbounded trusted header values', () => {
		for (const value of ['not-an-ip', '999.1.2.3', '203.0.113.1 attacker', '1'.repeat(65)]) {
			const request = new Request('https://example.test', {
				headers: { 'cf-connecting-ip': value }
			})
			expect(getClientIP(request, { trustHeaders: ['cf-connecting-ip'] })).toBe('unknown')
		}
	})

	it('accepts bounded IPv6 addresses', () => {
		const request = new Request('https://example.test', {
			headers: { 'cf-connecting-ip': '2001:db8::1' }
		})
		expect(getClientIP(request, { trustHeaders: ['cf-connecting-ip'] })).toBe('2001:db8::1')
	})
})
