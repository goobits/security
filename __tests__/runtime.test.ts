import { afterEach, describe, expect, it, vi } from 'vitest'

import { isProductionRuntime } from '@goobits/security/runtime'

afterEach(() => {
	vi.unstubAllEnvs()
})

describe('runtime', () => {
	it('recognizes production and rejects explicit development modes', () => {
		vi.stubEnv('NODE_ENV', 'production')
		expect(isProductionRuntime()).toBe(true)

		vi.stubEnv('NODE_ENV', 'development')
		expect(isProductionRuntime()).toBe(false)

		vi.stubEnv('NODE_ENV', 'test')
		expect(isProductionRuntime()).toBe(false)
	})

	it('treats unset and unknown environments as production-safe', () => {
		vi.stubEnv('NODE_ENV', '')
		expect(isProductionRuntime()).toBe(true)

		vi.stubEnv('NODE_ENV', 'staging')
		expect(isProductionRuntime()).toBe(true)
	})
})
