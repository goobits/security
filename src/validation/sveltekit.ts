/**
 * SvelteKit request validation middleware using Zod v4 schemas.
 *
 * @module @goobits/security/validation/sveltekit
 */

import type { RequestEvent, RequestHandler } from '@sveltejs/kit'

import {
	BodyTooLargeError,
	readJsonBody,
	readRequestBodyBytes
} from '../_internal/BodyTooLargeError.js'
import { type Logger, resolveLogger } from '../logger.js'
import type { ValidatedData, ValidationSchemas } from '../validation.js'

export { BodyTooLargeError, readJsonBody, readRequestBodyBytes }

/** With Validation Options request or option shape for security middleware. */
export interface WithValidationOptions {
	/** Pluggable logger. Default: silent. */
	logger?: Logger
	/** Maximum JSON body size to parse. Default: 1 MiB. */
	maxBodyBytes?: number
	/**
	 * Override how validation errors are surfaced. By default returns a JSON
	 * response with `{ success: false, error, details }` and HTTP 400.
	 */
	onValidationError?(
		layer: 'body' | 'query' | 'params',
		issues: unknown,
		event: RequestEvent
	): Response | Promise<Response>
}

function jsonResponse(payload: unknown, status: number): Response {
	return new Response(JSON.stringify(payload), {
		status,
		headers: { 'Content-Type': 'application/json' }
	})
}

function defaultErrorResponse(
	layer: 'body' | 'query' | 'params',
	issues: unknown
): Response {
	const labels: Record<typeof layer, string> = {
		body: 'Invalid request body',
		query: 'Invalid query parameters',
		params: 'Invalid URL parameters'
	}
	return jsonResponse({ success: false, error: labels[layer], details: issues }, 400)
}

/**
 * Wrap a SvelteKit `RequestHandler` with declarative request validation.
 *
 * @example
 * ```ts
 * import { z } from 'zod'
 * import { withValidation } from '@goobits/security/validation/sveltekit'
 *
 * const schemas = {
 *   body: z.object({ email: z.email(), name: z.string().min(1) }),
 *   query: z.object({ source: z.string().optional() })
 * }
 *
 * export const POST = withValidation(schemas, async (event) => {
 *   const { body, query } = event.locals.validatedData
 *   // ...
 *   return new Response('OK')
 * })
 * ```
 */
export function withValidation<Body = unknown, Query = unknown, Params = unknown>(
	schemas: ValidationSchemas<Body, Query, Params>,
	handler: (event: RequestEvent & {
		locals: RequestEvent['locals'] & {
			validatedData: ValidatedData<Body, Query, Params>
		}
	}) => Response | Promise<Response>,
	options: WithValidationOptions = {}
): RequestHandler {
	const log = resolveLogger(options.logger)
	const onError = options.onValidationError ?? ((layer, issues) => defaultErrorResponse(layer, issues))

	return async (event) => {
		const { request, url, params } = event
		const validatedData: ValidatedData<Body, Query, Params> = {}

		try {
			if (schemas.body && request.method !== 'GET' && request.method !== 'HEAD') {
				const readOptions = options.maxBodyBytes === undefined
					? {}
					: { maxBytes: options.maxBodyBytes }
				const raw = await readJsonBody(request, readOptions)
				const result = await schemas.body.safeParseAsync(raw)
				if (!result.success) {
					log.warn('Request body validation failed', {
						path: url.pathname,
						issues: result.error.issues
					})
					return onError('body', result.error.issues, event)
				}
				validatedData.body = result.data
			}

			if (schemas.query) {
				const raw = Object.fromEntries(url.searchParams.entries())
				const result = await schemas.query.safeParseAsync(raw)
				if (!result.success) {
					log.warn('Query parameter validation failed', {
						path: url.pathname,
						issues: result.error.issues
					})
					return onError('query', result.error.issues, event)
				}
				validatedData.query = result.data
			}

			if (schemas.params) {
				const result = await schemas.params.safeParseAsync(params)
				if (!result.success) {
					log.warn('URL parameter validation failed', {
						path: url.pathname,
						issues: result.error.issues
					})
					return onError('params', result.error.issues, event)
				}
				validatedData.params = result.data
			}

			const eventWithLocals = event as RequestEvent & {
				locals: RequestEvent['locals'] & {
					validatedData: ValidatedData<Body, Query, Params>
				}
			}
			eventWithLocals.locals.validatedData = validatedData

			return await handler(eventWithLocals)
		} catch(error) {
			if (error instanceof BodyTooLargeError) {
				log.warn('Validation request body too large', {
					path: url.pathname,
					maxBytes: error.maxBytes
				})
				return jsonResponse({ success: false, error: 'Request body too large' }, 413)
			}

			log.error('Validation middleware error', {
				path: url.pathname,
				error: error instanceof Error ? error.message : String(error)
			})
			return jsonResponse({ success: false, error: 'Validation error' }, 500)
		}
	}
}
