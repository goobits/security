/**
 * Generic input validation helpers using Zod v4 schemas.
 *
 * @module @goobits/security/validation
 */

import type { z } from 'zod'

import { type Logger, resolveLogger } from './logger.js'

/** Validation Schemas request or option shape for security middleware. */
export interface ValidationSchemas<
	Body = unknown,
	Query = unknown,
	Params = unknown
> {
	/** Zod schema for a JSON body. */
	body?: z.ZodType<Body>
	/** Zod schema for parsed query input. */
	query?: z.ZodType<Query>
	/** Zod schema for parsed route params. */
	params?: z.ZodType<Params>
}

/** Validated Data request or option shape for security middleware. */
export interface ValidatedData<Body, Query, Params> {
	body?: Body
	query?: Query
	params?: Params
}

/** Input Validator Result typed model for security middleware. */
export type InputValidatorResult<T> =
	| { success: true; data: T }
	| { success: false; issues: z.core.$ZodIssue[] }

/**
 * Build a `(input) => Result` validator function from a Zod schema.
 *
 * @example
 * ```ts
 * import { z } from 'zod'
 * import { getInputValidator } from '@goobits/security/validation'
 *
 * const schema = z.object({ email: z.email() })  // Zod v4 syntax
 * const validate = getInputValidator(schema)
 *
 * const result = validate({ email: 'a@b.com' })
 * if (result.success) {
 *   console.log(result.data.email)
 * } else {
 *   console.error(result.issues)
 * }
 * ```
 */
export function getInputValidator<T>(
	schema: z.ZodType<T>,
	options: { logger?: Logger } = {}
): (input: unknown) => InputValidatorResult<T> {
	const log = resolveLogger(options.logger)
	return (input: unknown) => {
		const result = schema.safeParse(input)
		if (result.success) {
			return { success: true, data: result.data }
		}
		log.warn('Input validation failed', { issues: result.error.issues })
		return { success: false, issues: result.error.issues }
	}
}
