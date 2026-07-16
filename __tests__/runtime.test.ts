import { afterEach, describe, expect, it, vi } from 'vitest'

import { isProductionRuntime, readRuntimeEnv } from '../src/runtime.js'

describe('runtime environment', () => {
	afterEach(() => {
		vi.unstubAllEnvs()
	})

	it.each(['development', 'test'])('recognizes explicit %s mode', (mode) => {
		vi.stubEnv('NODE_ENV', mode)
		expect(isProductionRuntime()).toBe(false)
		expect(isProductionRuntime(mode)).toBe(false)
	})

	it.each(['production', 'staging', ''])('uses safe production behavior for %j mode', (mode) => {
		vi.stubEnv('NODE_ENV', mode)
		expect(isProductionRuntime()).toBe(true)
		expect(isProductionRuntime(mode)).toBe(true)
	})

	it('reads only non-empty environment values', () => {
		vi.stubEnv('SECURITY_RUNTIME_TEST', 'configured')
		expect(readRuntimeEnv('SECURITY_RUNTIME_TEST')).toBe('configured')
		vi.stubEnv('SECURITY_RUNTIME_TEST', '')
		expect(readRuntimeEnv('SECURITY_RUNTIME_TEST')).toBeUndefined()
	})

	it('treats an explicitly absent deployment binding as production-safe', () => {
		vi.stubEnv('NODE_ENV', 'test')

		expect(isProductionRuntime()).toBe(false)
		expect(isProductionRuntime(undefined)).toBe(true)
	})
})
