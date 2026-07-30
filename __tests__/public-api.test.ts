import { describe, expect, it } from 'vitest'

async function publicApiSurface() {
	const modules = await Promise.all([
		import('@goobits/security'),
		import('@goobits/security/admin-auth'),
		import('@goobits/security/alerting'),
		import('@goobits/security/audit'),
		import('@goobits/security/audit/d1'),
		import('@goobits/security/audit/sveltekit'),
		import('@goobits/security/crypto'),
		import('@goobits/security/crypto/aead'),
		import('@goobits/security/crypto/framed-aead'),
		import('@goobits/security/crypto/encoding'),
		import('@goobits/security/crypto/proof'),
		import('@goobits/security/crypto/signatures'),
		import('@goobits/security/csp'),
		import('@goobits/security/csrf'),
		import('@goobits/security/csrf/sveltekit'),
		import('@goobits/security/csrf-client'),
		import('@goobits/security/csrf-redis'),
		import('@goobits/security/http-credentials'),
		import('@goobits/security/identity'),
		import('@goobits/security/identity/did-wba'),
		import('@goobits/security/identity/http-signature'),
		import('@goobits/security/identity/principal'),
		import('@goobits/security/jwt'),
		import('@goobits/security/logger'),
		import('@goobits/security/principal-auth'),
		import('@goobits/security/rate-limit'),
		import('@goobits/security/rate-limit/sveltekit'),
		import('@goobits/security/recaptcha'),
		import('@goobits/security/redaction'),
		import('@goobits/security/request-body'),
		import('@goobits/security/request-origin'),
		import('@goobits/security/runtime'),
		import('@goobits/security/turnstile'),
		import('@goobits/security/validation'),
		import('@goobits/security/validation/simple'),
		import('@goobits/security/validation/sveltekit')
	])
	const names = [
		'.',
		'admin-auth',
		'alerting',
		'audit',
		'audit/d1',
		'audit/sveltekit',
		'crypto',
		'crypto/aead',
		'crypto/framed-aead',
		'crypto/encoding',
		'crypto/proof',
		'crypto/signatures',
		'csp',
		'csrf',
		'csrf/sveltekit',
		'csrf-client',
		'csrf-redis',
		'http-credentials',
		'identity',
		'identity/did-wba',
		'identity/http-signature',
		'identity/principal',
		'jwt',
		'logger',
		'principal-auth',
		'rate-limit',
		'rate-limit/sveltekit',
		'recaptcha',
		'redaction',
		'request-body',
		'request-origin',
		'runtime',
		'turnstile',
		'validation',
		'validation/simple',
		'validation/sveltekit'
	]
	return Object.fromEntries(
		names.map((name, index) => [name, Object.keys(modules[index] ?? {}).sort()])
	)
}

describe('@goobits/security public API', () => {
	it('pins every public entrypoint to an intentional export surface', async () => {
		const surface = await publicApiSurface()

		for (const exports of Object.values(surface)) {
			expect(exports.some((name) => name.startsWith('_'))).toBe(false)
			expect(exports).not.toContain('resolveLogger')
		}
		expect(surface).toMatchSnapshot()
	})
})
