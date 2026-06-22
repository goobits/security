import { describe, expect, it } from 'vitest'

import { createRedisCsrfStore, type RedisLike } from '../src/csrfRedis.js'

/**
 * In-memory stand-in for ioredis that satisfies the `RedisLike` interface.
 * Mirrors the `set ... PX ttlMs` semantic, keys auto-expire client-side.
 */
function makeFakeRedis(): RedisLike & { _state: Map<string, { value: string; expiresAt: number }> } {
	const state = new Map<string, { value: string; expiresAt: number }>()
	let scanKeys: string[] | null = null

	function gc(): void {
		const now = Date.now()
		for (const [ k, v ] of state.entries()) {
			if (v.expiresAt <= now) state.delete(k)
		}
	}

	return {
		_state: state,
		async get(key: string): Promise<string | null> {
			gc()
			return state.get(key)?.value ?? null
		},
		async set(key: string, value: string, _mode: 'PX', ttlMs: number): Promise<unknown> {
			state.set(key, { value, expiresAt: Date.now() + ttlMs })
			return 'OK'
		},
		async del(key: string): Promise<unknown> {
			return state.delete(key) ? 1 : 0
		},
		async scan(
			cursor: string,
			_matchMode: 'MATCH',
			pattern: string,
			_countMode: 'COUNT',
			count: number
		): Promise<[string, string[]]> {
			gc()
			// Trivial pattern-to-regex (only `*` is supported here).
			const re = new RegExp('^' + pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$')
			if (cursor === '0' && scanKeys === null) {
				scanKeys = Array.from(state.keys()).filter(k => re.test(k))
			}
			const matchingKeys = scanKeys ?? []
			const offset = Number(cursor)
			const nextOffset = offset + count
			const nextCursor = nextOffset >= matchingKeys.length ? '0' : String(nextOffset)
			const batch = matchingKeys.slice(offset, nextOffset)
			if (nextCursor === '0') scanKeys = null
			return [ nextCursor, batch ]
		}
	}
}

describe('createRedisCsrfStore', () => {
	it('set + get round-trips an expiry timestamp as a number', async () => {
		const client = makeFakeRedis()
		const store = createRedisCsrfStore({ client })

		const expiresAt = Date.now() + 60_000
		await store.set('token-a', expiresAt, 60_000)
		const got = await store.get('token-a')
		expect(got).toBe(expiresAt)
	})

	it('get returns undefined for missing tokens', async () => {
		const client = makeFakeRedis()
		const store = createRedisCsrfStore({ client })

		expect(await store.get('does-not-exist')).toBeUndefined()
	})

	it('get returns undefined when the stored value is not a number', async () => {
		const client = makeFakeRedis()
		// Manually corrupt the state with a non-numeric value.
		client._state.set('csrf:bad', { value: 'not-a-number', expiresAt: Date.now() + 60_000 })

		const store = createRedisCsrfStore({ client })
		expect(await store.get('bad')).toBeUndefined()
	})

	it('delete removes a token', async () => {
		const client = makeFakeRedis()
		const store = createRedisCsrfStore({ client })

		await store.set('token-a', Date.now() + 60_000, 60_000)
		await store.delete('token-a')
		expect(await store.get('token-a')).toBeUndefined()
	})

	it('clear removes every token under the prefix', async () => {
		const client = makeFakeRedis()
		const store = createRedisCsrfStore({ client, clearScanCount: 2, clearBatchSize: 1 })

		await store.set('a', Date.now() + 60_000, 60_000)
		await store.set('b', Date.now() + 60_000, 60_000)
		await store.set('c', Date.now() + 60_000, 60_000)

		await store.clear()

		expect(await store.get('a')).toBeUndefined()
		expect(await store.get('b')).toBeUndefined()
		expect(await store.get('c')).toBeUndefined()
	})

	it('respects custom keyPrefix', async () => {
		const client = makeFakeRedis()
		const store = createRedisCsrfStore({ client, keyPrefix: 'myapp:csrf' })

		await store.set('token-a', Date.now() + 60_000, 60_000)
		expect(client._state.has('myapp:csrf:token-a')).toBe(true)
	})

	it('re-throws on get failure (so failClosed downstream can act)', async () => {
		const client: RedisLike = {
			async get() { throw new Error('connection refused') },
			async set() { throw new Error('connection refused') },
			async del() { throw new Error('connection refused') },
			async scan() { throw new Error('connection refused') }
		}
		const store = createRedisCsrfStore({ client })

		await expect(store.get('x')).rejects.toThrow(/connection refused/)
		await expect(store.set('x', 1, 1)).rejects.toThrow(/connection refused/)
		await expect(store.delete('x')).rejects.toThrow(/connection refused/)
		await expect(store.clear()).rejects.toThrow(/connection refused/)
	})

	it('falls back to expiresAt-Date.now() when ttlMs is omitted', async () => {
		const client = makeFakeRedis()
		const store = createRedisCsrfStore({ client })

		const expiresAt = Date.now() + 30_000
		await store.set('token-a', expiresAt)
		const got = await store.get('token-a')
		expect(got).toBe(expiresAt)
	})
})
