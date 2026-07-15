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
		const [turnstile, rateLimit, validation, redaction, credentials, logger] = await Promise.all([
			import('@goobits/security/turnstile'),
			import('@goobits/security/rate-limit/sveltekit'),
			import('@goobits/security/validation/sveltekit'),
			import('@goobits/security/redaction'),
			import('@goobits/security/http-credentials'),
			import('@goobits/security/logger')
		])

		expect(turnstile.verifyTurnstile).toBeTypeOf('function')
		expect(rateLimit).toBeTypeOf('object')
		expect(validation.withValidation).toBeTypeOf('function')
		expect(redaction.redactSensitive).toBeTypeOf('function')
		expect(credentials.parseBearerToken).toBeTypeOf('function')
		expect(logger).not.toHaveProperty('resolveLogger')
	})
})
