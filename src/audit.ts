/**
 * Audit logging  -  structured event emission for security-sensitive operations.
 *
 * @module @goobits/security/audit
 */

import { resolveLogger } from './_internal/resolveLogger.js'
import type { Logger } from './logger.js'
import { safeErrorContext } from './logger.js'
import { DEFAULT_REDACT_KEYS, redactSensitive } from './redaction.js'

/** Audit Outcome typed model for audit logging. */
export type AuditOutcome = 'success' | 'failure' | 'denied' | 'error'

/** Audit Event request or option shape for audit logging. */
export interface AuditEvent {
	/** Action label, e.g. `'user.login'`, `'admin.export-data'`. */
	action: string
	/** ISO timestamp. */
	timestamp: string
	/** `success`, `failure`, `denied`, or `error`. */
	outcome: AuditOutcome
	/** ID of the actor performing the action (if known). */
	actorId?: string
	/** ID of the target resource (if applicable). */
	targetId?: string
	/** Client IP. */
	clientIp?: string
	/** User-Agent header. */
	userAgent?: string
	/** Session/correlation ID. */
	sessionId?: string
	/** Request URL. */
	url?: string
	/** Request method. */
	method?: string
	/** HTTP status returned. */
	status?: number
	/** Elapsed ms between start and completion. */
	durationMs?: number
	/** Free-form structured detail (filtered for sensitive data by the caller). */
	detail?: Record<string, unknown>
	/** Bounded error identity when `outcome === 'error'`; messages and stacks are excluded. */
	error?: { name: string; code?: string }
}

/** Audit Sink request or option shape for audit logging. */
export interface AuditSink {
	/**
	 * Write a single audit event. Implementations may queue, batch, or persist.
	 * May throw. `AuditLogger` applies its configured failure mode.
	 */
	record(event: AuditEvent): void | Promise<void>
}

/** Default sink: writes via the supplied `Logger.info` at INFO level. */
export function createLoggerSink(logger: Logger): AuditSink {
	return {
		record(event: AuditEvent): void {
			const safeEvent = redactSensitive(event) as Record<string, unknown>
			logger.info(`audit:${event.action}`, safeEvent)
		}
	}
}

/** Audit Logger request or option shape for audit logging. */
export interface AuditLogger {
	log(event: Partial<AuditEvent> & { action: string; outcome: AuditOutcome }): Promise<void>
}

/** Create Audit Logger Options request or option shape for audit logging. */
export interface CreateAuditLoggerOptions {
	sink?: AuditSink
	logger?: Logger
	/** Additional sensitive keys; Security defaults are always retained. */
	redactKeys?: ReadonlyArray<string>
	/** Throw when the sink fails, or report through the logger. Default: `report`. */
	failureMode?: 'report' | 'throw'
}

/**
 * Build an `AuditLogger` that writes through a sink.
 *
 * @example
 * ```ts
 * const auditor = createAuditLogger({ sink: myDatabaseSink })
 * await auditor.log({
 *   action: 'user.login',
 *   outcome: 'success',
 *   actorId: user.id,
 *   clientIp: getClientIP(request)
 * })
 * ```
 */
export function createAuditLogger(options: CreateAuditLoggerOptions = {}): AuditLogger {
	const log = resolveLogger(options.logger)
	const sink = options.sink ?? createLoggerSink(log)
	const redactKeys = Array.from(new Set([...DEFAULT_REDACT_KEYS, ...(options.redactKeys ?? [])]))
	const failureMode = options.failureMode ?? 'report'

	return {
		async log(partial): Promise<void> {
			// Caller-supplied timestamp wins (useful for replaying historical events);
			// omit `timestamp` in your partial to get the current time.
			const event = redactSensitive(
				{
					...partial,
					timestamp: partial.timestamp ?? new Date().toISOString()
				},
				{ keys: redactKeys }
			) as AuditEvent
			try {
				await sink.record(event)
			} catch (err) {
				log.error('Audit sink threw', { ...safeErrorContext(err), action: event.action })
				if (failureMode === 'throw') throw err
			}
		}
	}
}
