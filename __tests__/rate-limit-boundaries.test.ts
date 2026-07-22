import { readFile } from 'node:fs/promises'
import { describe, expect, it } from 'vitest'
import {
	D1RateLimitStore,
	MemoryRateLimitStore,
	createHmacRateLimitStore,
	createRateLimiter,
	createResilientRateLimitStore,
	getClientIP
} from '../src/rate-limit/index.js'
import { D1RateLimitStore as DirectD1RateLimitStore } from '../src/rate-limit/d1Store.js'
import { MemoryRateLimitStore as DirectMemoryRateLimitStore } from '../src/rate-limit/memoryStore.js'
import { createHmacRateLimitStore as directCreateHmacStore } from '../src/rate-limit/hmacStore.js'
import { createRateLimiter as directCreateRateLimiter } from '../src/rate-limit/limiter.js'
import { createResilientRateLimitStore as directCreateResilientStore } from '../src/rate-limit/resilientStore.js'
import { getClientIP as directGetClientIP } from '../src/rate-limit/clientIp.js'

const owners = {
	'clientIp.ts': ['GetClientIpOptions', 'getClientIP'],
	'd1Store.ts': ['D1RateLimitDatabase', 'D1RateLimitStoreOptions', 'D1RateLimitStore'],
	'hmacStore.ts': ['HmacRateLimitStoreOptions', 'createHmacRateLimitStore'],
	'limiter.ts': ['createRateLimiter'],
	'memoryStore.ts': ['MemoryRateLimitStoreOptions', 'MemoryRateLimitStore'],
	'resilientStore.ts': ['ResilientRateLimitStoreOptions', 'createResilientRateLimitStore'],
	'types.ts': [
		'RateLimitEntry',
		'RateLimitStore',
		'RateLimitWindow',
		'RateLimitConfig',
		'RateLimitResult',
		'RateLimiter'
	]
} as const

describe('rate-limit module boundaries', () => {
	it('keeps the published barrel identity-stable', () => {
		expect(D1RateLimitStore).toBe(DirectD1RateLimitStore)
		expect(MemoryRateLimitStore).toBe(DirectMemoryRateLimitStore)
		expect(createHmacRateLimitStore).toBe(directCreateHmacStore)
		expect(createRateLimiter).toBe(directCreateRateLimiter)
		expect(createResilientRateLimitStore).toBe(directCreateResilientStore)
		expect(getClientIP).toBe(directGetClientIP)
	})

	it('keeps each rate-limit concept with one implementation owner', async () => {
		const sources = new Map(
			await Promise.all(
				Object.keys(owners).map(
					async (file) =>
						[
							file,
							await readFile(new URL(`../src/rate-limit/${file}`, import.meta.url), 'utf8')
						] as const
				)
			)
		)

		for (const [expectedFile, names] of Object.entries(owners)) {
			for (const name of names) {
				const declaration = new RegExp(`export (?:interface|type|class|function) ${name}\\b`)
				expect(
					[...sources].filter(([, source]) => declaration.test(source)).map(([file]) => file),
					name
				).toEqual([expectedFile])
			}
		}
	})

	it('keeps the public entrypoint as a barrel only', async () => {
		const source = await readFile(new URL('../src/rate-limit/index.ts', import.meta.url), 'utf8')
		expect(source).not.toMatch(/^export (?:interface|type|class|function)\s+[A-Za-z_$]/m)
		expect(source).not.toContain('resolveLogger')
		expect(source).not.toContain('signHmac')
	})
})
