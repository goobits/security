/**
 * Audit logging — structured event emission for security-sensitive operations.
 *
 * @module @goobits/security/audit
 */

import { type Logger, resolveLogger } from './logger.js'

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
	/** Error info when `outcome === 'error'`. */
	error?: { message: string; name?: string }
}

/** Audit Sink request or option shape for audit logging. */
export interface AuditSink {
	/**
	 * Write a single audit event. Implementations may queue, batch, or persist.
	 * Should NOT throw — log internally and swallow errors.
	 */
	record(event: AuditEvent): void | Promise<void>
}

/** Default sink: writes via the supplied `Logger.info` at INFO level. */
export function createLoggerSink(logger: Logger): AuditSink {
	return {
		record(event: AuditEvent): void {
			logger.info(`audit:${ event.action }`, event as unknown as Record<string, unknown>)
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

	return {
		async log(partial): Promise<void> {
			// Caller-supplied timestamp wins (useful for replaying historical events);
			// omit `timestamp` in your partial to get the current time.
			const event: AuditEvent = {
				...partial,
				timestamp: partial.timestamp ?? new Date().toISOString()
			}
			try {
				await sink.record(event)
			} catch(err) {
				log.error('Audit sink threw', { error: String(err), action: event.action })
			}
		}
	}
}
