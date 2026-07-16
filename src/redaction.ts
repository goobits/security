/** Default secret-bearing field names removed from logs and audit payloads. */
export const DEFAULT_REDACT_KEYS = [
	'password',
	'password_hash',
	'passphrase',
	'token',
	'token_hash',
	'access_token',
	'refresh_token',
	'id_token',
	'session_token',
	'reset_token',
	'magic_link_token',
	'secret',
	'private_key',
	'encryption_key',
	'signing_key',
	'authorization',
	'cookie',
	'api_key',
	'apikey',
	'client_secret',
	'clientsecret',
	'credit_card',
	'creditcard',
	'cvv',
	'verification_token',
	'verificationtoken',
	'totp',
	'otp',
	'otp_hash',
	'backup_codes',
	'recovery_codes',
	'webauthn_challenge'
] as const

/** Stable replacement used for secret-bearing values. */
export const REDACTED_VALUE = '[redacted]'

/** Controls recursive redaction without coupling the primitive to application PII policy. */
export interface RedactionOptions {
	keys?: ReadonlyArray<string>
	keyPattern?: RegExp
	replacement?: string
	redactString?: (value: string) => string
	/** Remove matching object fields instead of retaining a replacement value. */
	omit?: boolean
}

function patternMatches(pattern: RegExp | undefined, value: string): boolean {
	if (!pattern) return false
	pattern.lastIndex = 0
	const matches = pattern.test(value)
	pattern.lastIndex = 0
	return matches
}

function normalizeSensitiveKey(key: string): string {
	return key.toLowerCase().replaceAll(/[^a-z0-9]/g, '')
}

/** Returns whether a field name belongs to a configured secret-bearing class. */
export function isSensitiveKey(
	key: string,
	options: Pick<RedactionOptions, 'keys' | 'keyPattern'> = {}
): boolean {
	const normalizedKeys = new Set((options.keys ?? DEFAULT_REDACT_KEYS).map(normalizeSensitiveKey))
	return normalizedKeys.has(normalizeSensitiveKey(key)) || patternMatches(options.keyPattern, key)
}

/** Recursively copies a value while removing configured secret-bearing fields. */
export function redactSensitive(input: unknown, options: RedactionOptions = {}): unknown {
	const replacement = options.replacement ?? REDACTED_VALUE
	const normalizedKeys = new Set((options.keys ?? DEFAULT_REDACT_KEYS).map(normalizeSensitiveKey))
	const matchesSensitiveKey = (key: string): boolean =>
		normalizedKeys.has(normalizeSensitiveKey(key)) || patternMatches(options.keyPattern, key)
	const seen = new WeakSet<object>()

	const visit = (value: unknown): unknown => {
		if (typeof value === 'string') return options.redactString?.(value) ?? value
		if (!value || typeof value !== 'object') return value
		if (seen.has(value)) return '[circular]'
		seen.add(value)

		if (value instanceof Error) {
			return {
				name: value.name,
				message: options.redactString?.(value.message) ?? value.message,
				...(value.stack ? { stack: options.redactString?.(value.stack) ?? value.stack } : {})
			}
		}
		if (Array.isArray(value)) return value.map(visit)
		if (value instanceof Date) {
			return Number.isNaN(value.getTime()) ? null : value.toISOString()
		}
		if (value instanceof URL) return value.toString()

		const output: Record<string, unknown> = {}
		for (const [key, nested] of Object.entries(value)) {
			if (matchesSensitiveKey(key)) {
				if (!options.omit) output[key] = replacement
				continue
			}
			output[key] = visit(nested)
		}
		return output
	}

	return visit(input)
}

/** Recursively copies a value while omitting secret-bearing object fields. */
export function omitSensitive(
	input: unknown,
	options: Omit<RedactionOptions, 'omit' | 'replacement'> = {}
): unknown {
	return redactSensitive(input, { ...options, omit: true })
}
