/**
 * Lightweight schema validators for apps that do not need a Zod dependency at
 * the route boundary.
 *
 * @module @goobits/security/validation/simple
 */

export interface ValidationOptions {
	required?: boolean
	minLength?: number
	maxLength?: number
	min?: number
	max?: number
	pattern?: RegExp
	enum?: readonly string[]
	custom?: (value: unknown) => boolean | string
}

export type ValidationIssueCode =
	| 'required'
	| 'invalid_format'
	| 'too_short'
	| 'too_long'
	| 'invalid_range'

export interface ValidationIssue {
	code: ValidationIssueCode
	field: string
	message: string
	format?: string
	min?: number
	max?: number
	minLength?: number
	maxLength?: number
}

export type ValidationResult<T = unknown> =
	| { isValid: true; value: T | undefined }
	| { isValid: false; issue: ValidationIssue }

export type FieldValidator<T = unknown> = (
	value: unknown,
	fieldName: string
) => ValidationResult<T>

export class RequestValidationError extends Error {
	constructor(readonly issue: ValidationIssue) {
		super(issue.message)
		this.name = 'RequestValidationError'
	}
}

export function validateString(
	value: unknown,
	fieldName: string,
	options: ValidationOptions = {}
): ValidationResult<string> {
	const requiredResult = validateRequired(value, fieldName, options)
	if (requiredResult) return requiredResult

	if (isOptionalEmpty(value, options)) {
		return { isValid: true, value: undefined }
	}

	if (typeof value !== 'string') {
		return invalidFormat(fieldName, 'must be a string')
	}

	if (options.minLength !== undefined && value.length < options.minLength) {
		return tooShort(fieldName, options.minLength)
	}

	if (options.maxLength !== undefined && value.length > options.maxLength) {
		return tooLong(fieldName, options.maxLength)
	}

	if (options.pattern && !options.pattern.test(value)) {
		return invalidFormat(fieldName, 'does not match required pattern')
	}

	if (options.enum && !options.enum.includes(value)) {
		return invalidFormat(fieldName, `must be one of: ${options.enum.join(', ')}`)
	}

	const customResult = options.custom?.(value)
	if (customResult !== undefined && customResult !== true) {
		return invalidFormat(
			fieldName,
			typeof customResult === 'string'
				? customResult
				: 'custom validation failed'
		)
	}

	return { isValid: true, value }
}

export function validateNumber(
	value: unknown,
	fieldName: string,
	options: ValidationOptions = {}
): ValidationResult<number> {
	const requiredResult = validateRequired(value, fieldName, options)
	if (requiredResult) return requiredResult

	if (isOptionalEmpty(value, options)) {
		return { isValid: true, value: undefined }
	}

	let numberValue: number
	if (typeof value === 'number') {
		numberValue = value
	} else if (typeof value === 'string') {
		numberValue = Number(value)
	} else {
		return invalidFormat(fieldName, 'must be a number')
	}

	if (!Number.isFinite(numberValue)) {
		return invalidFormat(fieldName, 'must be a valid number')
	}

	if (options.min !== undefined && numberValue < options.min) {
		return invalidRange(fieldName, options.min, options.max)
	}

	if (options.max !== undefined && numberValue > options.max) {
		return invalidRange(fieldName, options.min, options.max)
	}

	const customResult = options.custom?.(numberValue)
	if (customResult !== undefined && customResult !== true) {
		return invalidFormat(
			fieldName,
			typeof customResult === 'string'
				? customResult
				: 'custom validation failed'
		)
	}

	return { isValid: true, value: numberValue }
}

export function validateBoolean(
	value: unknown,
	fieldName: string,
	options: ValidationOptions = {}
): ValidationResult<boolean> {
	const requiredResult = validateRequired(value, fieldName, options)
	if (requiredResult) return requiredResult

	if (isOptionalEmpty(value, options)) {
		return { isValid: true, value: undefined }
	}

	if (typeof value === 'boolean') {
		return { isValid: true, value }
	}

	if (typeof value === 'string') {
		if (value.toLowerCase() === 'true') return { isValid: true, value: true }
		if (value.toLowerCase() === 'false') return { isValid: true, value: false }
		return invalidFormat(fieldName, 'must be a boolean')
	}

	return { isValid: true, value: Boolean(value) }
}

export function validateArray<T>(
	value: unknown,
	fieldName: string,
	itemValidator?: (item: unknown, index: number) => ValidationResult<T>,
	options: ValidationOptions = {}
): ValidationResult<T[] | unknown[]> {
	const requiredResult = validateRequired(value, fieldName, options)
	if (requiredResult) return requiredResult

	if (isOptionalEmpty(value, options)) {
		return { isValid: true, value: undefined }
	}

	if (!Array.isArray(value)) {
		return invalidFormat(fieldName, 'must be an array')
	}

	if (options.minLength !== undefined && value.length < options.minLength) {
		return tooShort(fieldName, options.minLength)
	}

	if (options.maxLength !== undefined && value.length > options.maxLength) {
		return tooLong(fieldName, options.maxLength)
	}

	if (!itemValidator) {
		return { isValid: true, value }
	}

	const validatedItems: T[] = []
	for (let index = 0; index < value.length; index++) {
		const itemResult = itemValidator(value[index], index)
		if (!itemResult.isValid) {
			return invalidFormat(
				fieldName,
				`item at index ${index}: ${itemResult.issue.message}`
			)
		}
		validatedItems.push(itemResult.value as T)
	}

	return { isValid: true, value: validatedItems }
}

export function validateObject<T extends Record<string, unknown>>(
	value: unknown,
	fieldName: string,
	schema: Record<keyof T, FieldValidator>,
	options: ValidationOptions = {}
): ValidationResult<T> {
	const requiredResult = validateRequired(value, fieldName, options)
	if (requiredResult) return requiredResult

	if (isOptionalEmpty(value, options)) {
		return { isValid: true, value: undefined }
	}

	if (typeof value !== 'object' || value === null || Array.isArray(value)) {
		return invalidFormat(fieldName, 'must be an object')
	}

	const objectValue = value as Record<string, unknown>
	const validatedObject: Partial<T> = {}

	for (const [key, validator] of Object.entries(schema)) {
		const fieldResult = validator(objectValue[key], `${fieldName}.${key}`)
		if (!fieldResult.isValid) {
			return fieldResult
		}
		if (fieldResult.value !== undefined) {
			validatedObject[key as keyof T] = fieldResult.value as T[keyof T]
		}
	}

	return { isValid: true, value: validatedObject as T }
}

export async function validateRequestBody<T extends Record<string, unknown>>(
	request: Request,
	schema: Record<keyof T, FieldValidator>
): Promise<T> {
	let data: unknown

	try {
		data = await request.json()
	} catch {
		throw new RequestValidationError(
			createIssue('invalid_format', 'request body', 'request body has invalid format: must be valid JSON', {
				format: 'must be valid JSON'
			})
		)
	}

	const result = validateObject<T>(data, 'request body', schema, {
		required: true
	})
	if (!result.isValid) {
		throw new RequestValidationError(result.issue)
	}

	return result.value as T
}

function validateRequired(
	value: unknown,
	fieldName: string,
	options: ValidationOptions
): ValidationResult<never> | null {
	if (options.required && (value === undefined || value === null || value === '')) {
		return {
			isValid: false,
			issue: createIssue('required', fieldName, `${fieldName} is required`)
		}
	}

	return null
}

function isOptionalEmpty(value: unknown, options: ValidationOptions): boolean {
	return !options.required && (value === undefined || value === null)
}

function invalidFormat(fieldName: string, format: string): ValidationResult<never> {
	return {
		isValid: false,
		issue: createIssue(
			'invalid_format',
			fieldName,
			`${fieldName} has invalid format: ${format}`,
			{ format }
		)
	}
}

function tooShort(fieldName: string, minLength: number): ValidationResult<never> {
	return {
		isValid: false,
		issue: createIssue(
			'too_short',
			fieldName,
			`${fieldName} must be at least ${minLength} characters`,
			{ minLength }
		)
	}
}

function tooLong(fieldName: string, maxLength: number): ValidationResult<never> {
	return {
		isValid: false,
		issue: createIssue(
			'too_long',
			fieldName,
			`${fieldName} must be ${maxLength} characters or less`,
			{ maxLength }
		)
	}
}

function invalidRange(
	fieldName: string,
	min: number | undefined,
	max: number | undefined
): ValidationResult<never> {
	const format =
		min !== undefined && max !== undefined
			? `must be between ${min} and ${max}`
			: min !== undefined
				? `must be at least ${min}`
				: `must be at most ${max}`

	return {
		isValid: false,
		issue: createIssue(
			'invalid_range',
			fieldName,
			`${fieldName} has invalid format: ${format}`,
			{ format, min, max }
		)
	}
}

function createIssue(
	code: ValidationIssueCode,
	field: string,
	message: string,
	details: Omit<ValidationIssue, 'code' | 'field' | 'message'> = {}
): ValidationIssue {
	return {
		code,
		field,
		message,
		...details
	}
}
