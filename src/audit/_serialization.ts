import { DEFAULT_REDACT_KEYS, redactSensitive } from '../redaction.js'

export function validateAuditSinkLimits(prefix: string, maxDetailBytes: number, maxFieldLength: number): void {
	if (!Number.isSafeInteger(maxDetailBytes) || maxDetailBytes < 256) {
		throw new Error(`${prefix}: maxDetailBytes must be an integer of at least 256`)
	}
	if (!Number.isSafeInteger(maxFieldLength) || maxFieldLength < 64) {
		throw new Error(`${prefix}: maxFieldLength must be an integer of at least 64`)
	}
}

export function resolveAuditRedactKeys(redactKeys: ReadonlyArray<string> | undefined): string[] {
	return Array.from(new Set([...DEFAULT_REDACT_KEYS, ...(redactKeys ?? [])]))
}

export function serializeAuditDetail(
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

export function boundedAuditField(value: string | undefined, maxLength: number): string | null {
	return value === undefined ? null : value.slice(0, maxLength)
}
