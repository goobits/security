import { describe, expect, it } from 'vitest'

import {
	createLoginRateLimiter,
	createPasswordResetRateLimiter,
	createRegistrationRateLimiter
} from '../src/rate-limit/auth.js'

describe('createLoginRateLimiter', () => {
	it('allows 5 attempts within the burst window and blocks the 6th', async () => {
		const limiter = createLoginRateLimiter()
		for (let i = 0; i < 5; i++) {
			const v = await limiter.check('alice')
			expect(v.allowed).toBe(true)
		}
		const blocked = await limiter.check('alice')
		expect(blocked.allowed).toBe(false)
		if (!blocked.allowed) expect(blocked.window).toMatch(/^login:/)
	})

	it('isolates identifiers', async () => {
		const limiter = createLoginRateLimiter()
		for (let i = 0; i < 5; i++) await limiter.check('alice')
		const bob = await limiter.check('bob')
		expect(bob.allowed).toBe(true)
	})
})

describe('createRegistrationRateLimiter', () => {
	it('allows 3 registrations within 10min and blocks the 4th', async () => {
		const limiter = createRegistrationRateLimiter()
		for (let i = 0; i < 3; i++) {
			expect((await limiter.check('192.0.2.1')).allowed).toBe(true)
		}
		const blocked = await limiter.check('192.0.2.1')
		expect(blocked.allowed).toBe(false)
	})
})

describe('createPasswordResetRateLimiter', () => {
	it('allows 3 requests within 15min and blocks the 4th', async () => {
		const limiter = createPasswordResetRateLimiter()
		for (let i = 0; i < 3; i++) {
			expect((await limiter.check('a@b.com')).allowed).toBe(true)
		}
		const blocked = await limiter.check('a@b.com')
		expect(blocked.allowed).toBe(false)
	})
})
