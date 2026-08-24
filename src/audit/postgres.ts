import { resolveLogger } from '../_internal/resolveLogger.js'
import type { AuditEvent, AuditSink } from '../audit.js'
import type { Logger } from '../logger.js'
import {
	boundedAuditField,
	resolveAuditRedactKeys,
	serializeAuditDetail,
	validateAuditSinkLimits
} from './_serialization.js'

export interface PostgresAuditDatabase {
	query(sql: string, params?: readonly unknown[]): Promise<unknown>
}

export interface PostgresAuditSinkOptions {
	db: PostgresAuditDatabase
	/** Stable application name stored with every event. */
	application: string
	tableName?: string
	maxDetailBytes?: number
	maxFieldLength?: number
	/** Additional keys; Security's default secret keys are always included. */
	redactKeys?: ReadonlyArray<string>
	logger?: Logger
}

const SQL_IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/

/** Creates a bounded, secret-redacting PostgreSQL audit sink. */
export function createPostgresAuditSink({
	db,
	application,
	tableName = 'security_audit_events',
	maxDetailBytes = 16_384,
	maxFieldLength = 2_048,
	redactKeys,
	logger
}: PostgresAuditSinkOptions): AuditSink {
	if (!SQL_IDENTIFIER.test(tableName)) {
		throw new Error('@goobits/security/audit: invalid PostgreSQL audit table name')
	}
	const normalizedApplication = application.trim()
	if (!normalizedApplication || normalizedApplication.length > 64) {
		throw new Error('@goobits/security/audit: application must contain 1 to 64 characters')
	}
	validateAuditSinkLimits('@goobits/security/audit', maxDetailBytes, maxFieldLength)
	const resolvedRedactKeys = resolveAuditRedactKeys(redactKeys)
	const log = resolveLogger(logger)
	const table = `"${tableName}"`

	return {
		async record(event: AuditEvent): Promise<void> {
			try {
				await db.query(
					`INSERT INTO ${table} (
						application, action, outcome, actor_id, target_id, client_ip,
						user_agent, session_id, url, method, status, duration_ms,
						detail, error_name, error_code, occurred_at
					) VALUES (
						$1, $2, $3, $4, $5, $6, $7, $8,
						$9, $10, $11, $12, $13::jsonb, $14, $15, $16::timestamptz
					)`,
					[
						normalizedApplication,
						boundedAuditField(event.action, maxFieldLength),
						event.outcome,
						boundedAuditField(event.actorId, maxFieldLength),
						boundedAuditField(event.targetId, maxFieldLength),
						boundedAuditField(event.clientIp, maxFieldLength),
						boundedAuditField(event.userAgent, maxFieldLength),
						boundedAuditField(event.sessionId, maxFieldLength),
						boundedAuditField(event.url, maxFieldLength),
						boundedAuditField(event.method, maxFieldLength),
						event.status ?? null,
						event.durationMs ?? null,
						serializeAuditDetail(event.detail, maxDetailBytes, resolvedRedactKeys),
						boundedAuditField(event.error?.name, maxFieldLength),
						boundedAuditField(event.error?.code, maxFieldLength),
						boundedAuditField(event.timestamp, maxFieldLength)
					]
				)
			} catch (error) {
				log.error('@goobits/security/audit: PostgreSQL audit write failed', {
					action: event.action,
					error_type: error instanceof Error ? error.name : 'UnknownError'
				})
				throw error
			}
		}
	}
}
