import { describe, expect, it } from 'vitest'

describe('@goobits/security public API', () => {
	it('exposes the root security primitives', async () => {
		const api = await import('@goobits/security')

		expect(api).toMatchObject({
			createAdminAuth: expect.any(Function),
			createCsrf: expect.any(Function),
			createRateLimiter: expect.any(Function),
			createSecurityAlerter: expect.any(Function),
			SECURITY_PACKAGE_VERSION: expect.any(String)
		})
	})

	it('resolves framework and provider subpath exports', async () => {
		const [turnstile, csrf, rateLimit, validation] = await Promise.all([
			import('@goobits/security/turnstile'),
			import('@goobits/security/csrf/sveltekit'),
			import('@goobits/security/rate-limit/sveltekit'),
			import('@goobits/security/validation/sveltekit')
		])

		expect(turnstile.verifyTurnstile).toBeTypeOf('function')
		expect(csrf.createSvelteKitCsrf).toBeTypeOf('function')
		expect(rateLimit).toBeTypeOf('object')
		expect(validation.withValidation).toBeTypeOf('function')
	})
})
