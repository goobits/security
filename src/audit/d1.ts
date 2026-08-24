import type { AuditEvent, AuditSink } from '../audit.js'
import { resolveLogger } from '../_internal/resolveLogger.js'
import type { Logger } from '../logger.js'
import {
	boundedAuditField,
	resolveAuditRedactKeys,
	serializeAuditDetail,
	validateAuditSinkLimits
} from './_serialization.js'

type D1PreparedStatementLike = {
	bind: (...values: unknown[]) => { run: () => Promise<unknown> }
}

export interface D1AuditDatabase {
	prepare(sql: string): D1PreparedStatementLike
}

export interface D1AuditSinkOptions {
	db: D1AuditDatabase
	tableName?: string
	maxDetailBytes?: number
	maxFieldLength?: number
	/** Additional keys; Security's default secret keys are always included. */
	redactKeys?: ReadonlyArray<string>
	logger?: Logger
}

const SQL_IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/

/** Creates a secret-redacting D1 sink for Security's canonical audit logger. */
export function createD1AuditSink({
	db,
	tableName = 'security_audit_events',
	maxDetailBytes = 16_384,
	maxFieldLength = 2_048,
	redactKeys,
	logger
}: D1AuditSinkOptions): AuditSink {
	if (!SQL_IDENTIFIER.test(tableName)) {
		throw new Error('@goobits/security/audit: invalid D1 audit table name')
	}
	validateAuditSinkLimits('@goobits/security/audit', maxDetailBytes, maxFieldLength)
	const resolvedRedactKeys = resolveAuditRedactKeys(redactKeys)
	const log = resolveLogger(logger)
	return {
		async record(event: AuditEvent): Promise<void> {
			try {
				await db
					.prepare(
						`INSERT INTO ${tableName} (
							action, outcome, actor_id, target_id, client_ip, user_agent,
							session_id, url, method, status, duration_ms, detail_json,
							error_name, error_message, occurred_at
						) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
					)
					.bind(
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
						null,
						boundedAuditField(event.timestamp, maxFieldLength)
					)
					.run()
			} catch (error) {
				log.error('@goobits/security/audit: D1 audit write failed', {
					action: event.action,
					error_type: error instanceof Error ? error.name : 'UnknownError'
				})
				throw error
			}
		}
	}
}
