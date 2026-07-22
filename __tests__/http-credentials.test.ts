import { describe, expect, it, vi } from 'vitest'

import {
	createApiKey,
	createBasicAuthResponse,
	hashApiKey,
	parseApiKeyHeader,
	parseBasicAuthHeader,
	parseBearerToken,
	verifyApiKey,
	verifyBasicAuthHeader
} from '../src/httpCredentials.js'

const basicHeader = (username: string, password: string): string =>
	`Basic ${btoa(`${username}:${password}`)}`

describe('HTTP credential parsing', () => {
	it('accepts explicit schemes and rejects raw or malformed values', () => {
		expect(parseBearerToken('Bearer token-value')).toBe('token-value')
		expect(parseApiKeyHeader('ApiKey service-key')).toBe('service-key')
		expect(parseApiKeyHeader('Bearer service-key')).toBe('service-key')
		expect(parseApiKeyHeader('service-key')).toBeNull()
		expect(parseBearerToken('Bearer token with spaces')).toBeNull()
	})

	it('parses bounded Basic credentials', () => {
		expect(parseBasicAuthHeader(basicHeader('alice', 'secret'))).toEqual({
			username: 'alice',
			password: 'secret'
		})
		expect(parseBasicAuthHeader('Basic not-base64!')).toBeNull()
		expect(parseBasicAuthHeader(basicHeader('', 'secret'))).toBeNull()
	})

	it('performs a dummy password check for unknown usernames', async () => {
		const verifyPassword = vi.fn(async () => false)
		await expect(
			verifyBasicAuthHeader({
				authHeader: basicHeader('missing', 'guess'),
				getPasswordHash: async () => null,
				verifyPassword,
				dummyPasswordHash: 'dummy-hash'
			})
		).resolves.toBeNull()
		expect(verifyPassword).toHaveBeenCalledWith('dummy-hash', 'guess')
	})

	it('sanitizes Basic challenge realms', () => {
		const response = createBasicAuthResponse({ realm: 'Admin\r\n"Area"' })
		expect(response.status).toBe(401)
		expect(response.headers.get('www-authenticate')).toBe('Basic realm="Admin\\"Area\\""')
	})
})

describe('API-key verifiers', () => {
	const options = { secret: 'api-key-verifier-secret-that-is-at-least-32-bytes' } // gitleaks:allow -- deterministic test-only HMAC secret

	it('creates bounded random keys', () => {
		expect(createApiKey({ prefix: 'service', bytes: 16 })).toMatch(/^service_[0-9a-f]{32}$/)
		expect(() => createApiKey({ prefix: 'bad prefix' })).toThrow(/invalid API-key prefix/)
	})

	it('hashes and verifies without storing the submitted key', async () => {
		const verifier = await hashApiKey('service_secret', options)
		expect(verifier).toMatch(/^hmac-sha256:/)
		expect(verifier).not.toContain('service_secret')
		await expect(verifyApiKey('service_secret', verifier, options)).resolves.toBe(true)
		await expect(verifyApiKey('wrong', verifier, options)).resolves.toBe(false)
	})
})
