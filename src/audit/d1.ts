import type { AuditEvent, AuditSink } from '../audit.js'
import { resolveLogger } from '../_internal/resolveLogger.js'
import type { Logger } from '../logger.js'
import { DEFAULT_REDACT_KEYS, redactSensitive } from '../redaction.js'

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

function serializeDetail(
	detail: Record<string, unknown> | undefined,
	maxBytes: number,
	redactKeys: ReadonlyArray<string>
): string | null {
	if (!detail) return null
	const serialized = JSON.stringify(redactSensitive(detail, { keys: redactKeys }), (_key, value) =>
		typeof value === 'bigint' ? value.toString() : value
	)
	if (new TextEncoder().encode(serialized).byteLength <= maxBytes) return serialized
	return JSON.stringify({ truncated: true })
}

function bounded(value: string | undefined, maxLength: number): string | null {
	return value === undefined ? null : value.slice(0, maxLength)
}

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
	if (!Number.isSafeInteger(maxDetailBytes) || maxDetailBytes < 256) {
		throw new Error('@goobits/security/audit: maxDetailBytes must be an integer of at least 256')
	}
	if (!Number.isSafeInteger(maxFieldLength) || maxFieldLength < 64) {
		throw new Error('@goobits/security/audit: maxFieldLength must be an integer of at least 64')
	}
	const resolvedRedactKeys = Array.from(new Set([...DEFAULT_REDACT_KEYS, ...(redactKeys ?? [])]))
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
						bounded(event.action, maxFieldLength),
						event.outcome,
						bounded(event.actorId, maxFieldLength),
						bounded(event.targetId, maxFieldLength),
						bounded(event.clientIp, maxFieldLength),
						bounded(event.userAgent, maxFieldLength),
						bounded(event.sessionId, maxFieldLength),
						bounded(event.url, maxFieldLength),
						bounded(event.method, maxFieldLength),
						event.status ?? null,
						event.durationMs ?? null,
						serializeDetail(event.detail, maxDetailBytes, resolvedRedactKeys),
						bounded(event.error?.name, maxFieldLength),
						null,
						bounded(event.timestamp, maxFieldLength)
					)
					.run()
			} catch (error) {
				log.error('@goobits/security/audit: D1 audit write failed', {
					action: event.action,
					error: error instanceof Error ? error.name : 'UnknownError'
				})
			}
		}
	}
}
