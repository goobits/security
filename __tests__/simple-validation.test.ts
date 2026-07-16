import { describe, expect, it } from 'vitest'

import {
	RequestValidationError,
	validateArray,
	validateBoolean,
	validateNumber,
	validateRequestBody,
	validateString
} from '../src/validation/simple.js'

describe('simple validation helpers', () => {
	it('validates strings with required, length, pattern, and enum constraints', () => {
		expect(
			validateString('draft', 'status', {
				required: true,
				minLength: 2,
				maxLength: 10,
				pattern: /^[a-z]+$/,
				enum: ['draft', 'published']
			})
		).toEqual({ isValid: true, value: 'draft' })

		const result = validateString('', 'status', { required: true })
		expect(result.isValid).toBe(false)
		if (!result.isValid) expect(result.issue.code).toBe('required')
	})

	it('validates numeric strings and range failures', () => {
		expect(validateNumber('5', 'limit', { min: 1, max: 10 })).toEqual({
			isValid: true,
			value: 5
		})

		const result = validateNumber(11, 'limit', { min: 1, max: 10 })
		expect(result.isValid).toBe(false)
		if (!result.isValid) {
			expect(result.issue.code).toBe('invalid_range')
			expect(result.issue.min).toBe(1)
			expect(result.issue.max).toBe(10)
		}
	})

	it('rejects blank numeric strings and non-boolean values without coercion', () => {
		for (const value of [' ', '\t', '\n']) {
			expect(validateNumber(value, 'limit').isValid).toBe(false)
		}

		expect(validateBoolean(true, 'enabled')).toEqual({ isValid: true, value: true })
		expect(validateBoolean('false', 'enabled')).toEqual({ isValid: true, value: false })
		for (const value of [{}, [], 0, 1, Number.NaN]) {
			expect(validateBoolean(value, 'enabled').isValid).toBe(false)
		}
	})

	it('validates arrays with item validators', () => {
		const result = validateArray(
			['one', 'two'],
			'tags',
			(item) => validateString(item, 'tag', { minLength: 1 }),
			{ maxLength: 3 }
		)

		expect(result).toEqual({ isValid: true, value: ['one', 'two'] })
	})

	it('validates JSON request bodies through object schemas', async () => {
		const request = new Request('https://example.test/api', {
			method: 'POST',
			body: JSON.stringify({ name: 'Inbox' })
		})

		const data = await validateRequestBody<{ name: string }>(request, {
			name: (value, fieldName) => validateString(value, fieldName, { required: true })
		})

		expect(data).toEqual({ name: 'Inbox' })
	})

	it('throws structured errors for invalid JSON request bodies', async () => {
		const request = new Request('https://example.test/api', {
			method: 'POST',
			body: '{'
		})

		await expect(
			validateRequestBody<{ name: string }>(request, {
				name: (value, fieldName) => validateString(value, fieldName, { required: true })
			})
		).rejects.toBeInstanceOf(RequestValidationError)
	})
})
