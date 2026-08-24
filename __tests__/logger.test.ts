import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { createConsoleLogger, noopLogger, safeErrorContext } from '../src/logger.js'

describe('safeErrorContext', () => {
	it('uses the canonical error field without exposing the message', () => {
		const context = safeErrorContext(new Error('private detail'))
		expect(context).toEqual({ error_type: 'Error' })
		expect(JSON.stringify(context)).not.toContain('private detail')
	})
})

describe('noopLogger', () => {
	it('exposes all four methods and swallows calls', () => {
		expect(() => noopLogger.debug('x')).not.toThrow()
		expect(() => noopLogger.info('x')).not.toThrow()
		expect(() => noopLogger.warn('x')).not.toThrow()
		expect(() => noopLogger.error('x')).not.toThrow()
	})
})

describe('createConsoleLogger', () => {
	const spies = {
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn()
	}

	beforeEach(() => {
		vi.spyOn(console, 'debug').mockImplementation(spies.debug)
		vi.spyOn(console, 'info').mockImplementation(spies.info)
		vi.spyOn(console, 'warn').mockImplementation(spies.warn)
		vi.spyOn(console, 'error').mockImplementation(spies.error)
		Object.values(spies).forEach((s) => s.mockClear())
	})

	afterEach(() => {
		vi.restoreAllMocks()
	})

	it('emits all levels at default (info)', () => {
		const log = createConsoleLogger()
		log.debug('d')
		log.info('i')
		log.warn('w')
		log.error('e')
		// debug suppressed by default level=info
		expect(spies.debug).not.toHaveBeenCalled()
		expect(spies.info).toHaveBeenCalledWith('i')
		expect(spies.warn).toHaveBeenCalledWith('w')
		expect(spies.error).toHaveBeenCalledWith('e')
	})

	it('honors level filter', () => {
		const log = createConsoleLogger({ level: 'warn' })
		log.debug('d')
		log.info('i')
		log.warn('w')
		log.error('e')
		expect(spies.debug).not.toHaveBeenCalled()
		expect(spies.info).not.toHaveBeenCalled()
		expect(spies.warn).toHaveBeenCalled()
		expect(spies.error).toHaveBeenCalled()
	})

	it('applies prefix', () => {
		const log = createConsoleLogger({ prefix: '[svc]' })
		log.info('hello')
		expect(spies.info).toHaveBeenCalledWith('[svc] hello')
	})

	it('passes context as second argument', () => {
		const log = createConsoleLogger({ level: 'debug' })
		log.debug('hello', { traceId: 'abc' })
		expect(spies.debug).toHaveBeenCalledWith('hello', { traceId: 'abc' })
	})

	it('omits context arg when not provided', () => {
		const log = createConsoleLogger({ level: 'debug' })
		log.debug('hello')
		expect(spies.debug).toHaveBeenCalledWith('hello')
	})
})
