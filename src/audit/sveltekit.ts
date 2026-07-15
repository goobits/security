/**
 * SvelteKit audit helpers.
 *
 * @module @goobits/security/audit/sveltekit
 */

import type { RequestEvent, RequestHandler } from '@sveltejs/kit'

import { BodyTooLargeError, readJsonBody } from '../_internal/BodyTooLargeError.js'
import type { AuditEvent, AuditLogger, AuditOutcome } from '../audit.js'
import { resolveLogger } from '../_internal/resolveLogger.js'
import type { Logger } from '../logger.js'
import { DEFAULT_REDACT_KEYS, redactSensitive } from '../redaction.js'

/** With Audit Options request or option shape for audit logging. */
export interface WithAuditOptions {
	/** Action label. */
	action: string
	/**
	 * If true, captures the request body into `event.detail.requestBody`.
	 * **DANGEROUS for routes carrying credentials** (login, password reset,
	 * payment). Use `redactKeys` to strip sensitive fields. Default: false.
	 */
	includeRequestBody?: boolean
	/**
	 * When `includeRequestBody` is true, top-level keys to redact from the
	 * captured body before logging. Default: `['password', 'token', 'secret',
	 * 'apiKey', 'authorization', 'creditCard', 'cvv']`. Pass `[]` to disable
	 * redaction (not recommended).
	 */
	redactKeys?: string[]
	/** Maximum request body bytes to capture when `includeRequestBody` is true. Default: 64 KiB. */
	maxRequestBodyBytes?: number
	/** Audit logger to write to. */
	auditor: AuditLogger
	/** Resolves the actor ID from the SvelteKit event. */
	actorId?(event: RequestEvent): string | undefined
	/** Resolves additional detail to attach to the audit event. */
	detail?(event: RequestEvent): Record<string, unknown> | undefined
	/** Pluggable logger. Default: silent. */
	logger?: Logger
}

/**
 * Wrap a SvelteKit `RequestHandler` to automatically emit one audit event
 * per invocation. Captures method, URL, status, and duration.
 *
 * Outcome is derived from the response: 2xx-3xx -> `success`, 401/403 ->
 * `denied`, thrown exception -> `error`, otherwise -> `failure`.
 *
 * **Fire-and-forget**: the audit event is dispatched without awaiting the
 * sink. The handler's response goes out as soon as the handler completes,
 * not after the audit lands. For compliance contexts that require the audit
 * record to be durably stored before the user sees the response, do not use
 * `withAudit` - call `auditor.log()` explicitly with `await` before returning.
 *
 * @example
 * ```ts
 * export const POST = withAudit(
 *   { action: 'admin.delete-user', auditor, actorId: e => e.locals.user?.id },
 *   async (event) => {
 *     // ... your logic ...
 *     return new Response('OK')
 *   }
 * )
 * ```
 */
export function withAudit(options: WithAuditOptions, handler: RequestHandler): RequestHandler {
	const log = resolveLogger(options.logger)
	const redactKeys = options.redactKeys ?? DEFAULT_REDACT_KEYS

	return async (event) => {
		const startedAt = Date.now()
		const baseDetail = options.detail?.(event) ?? {}
		let requestBody: unknown

		if (
			options.includeRequestBody &&
			event.request.method !== 'GET' &&
			event.request.method !== 'HEAD'
		) {
			try {
				const raw = await readJsonBody(event.request.clone(), {
					maxBytes: options.maxRequestBodyBytes ?? 65_536
				})
				requestBody = redactSensitive(raw, { keys: redactKeys })
			} catch (err) {
				log.debug('audit: could not capture request body', {
					error: err instanceof BodyTooLargeError ? 'body-too-large' : String(err)
				})
			}
		}

		let response: Response | undefined
		let thrown: unknown

		try {
			response = await handler(event)
			return response
		} catch (err) {
			thrown = err
			throw err
		} finally {
			const durationMs = Date.now() - startedAt
			const status = response?.status ?? (thrown ? 500 : 0)
			const outcome: AuditOutcome = thrown
				? 'error'
				: status >= 200 && status < 400
					? 'success'
					: status === 401 || status === 403
						? 'denied'
						: 'failure'

			const auditEvent: Partial<AuditEvent> & { action: string; outcome: AuditOutcome } = {
				action: options.action,
				outcome,
				method: event.request.method,
				url: event.url.toString(),
				status,
				durationMs,
				detail: requestBody === undefined ? baseDetail : { ...baseDetail, requestBody }
			}
			const actorId = options.actorId?.(event)
			if (actorId) auditEvent.actorId = actorId
			if (thrown instanceof Error) {
				auditEvent.error = { message: thrown.message, name: thrown.name }
			}

			void options.auditor.log(auditEvent)
		}
	}
}
