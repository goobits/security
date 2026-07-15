/** Default secret-bearing field names removed from logs and audit payloads. */
export const DEFAULT_REDACT_KEYS = [
	'password',
	'passphrase',
	'token',
	'access_token',
	'refresh_token',
	'secret',
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
	'otp'
] as const

/** Stable replacement used for secret-bearing values. */
export const REDACTED_VALUE = '[redacted]'

/** Controls recursive redaction without coupling the primitive to application PII policy. */
export interface RedactionOptions {
	keys?: ReadonlyArray<string>
	keyPattern?: RegExp
	replacement?: string
	redactString?: (value: string) => string
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
	if (typeof value !== 'object' || value === null) return false
	const prototype = Object.getPrototypeOf(value)
	return prototype === Object.prototype || prototype === null
}

function patternMatches(pattern: RegExp | undefined, value: string): boolean {
	if (!pattern) return false
	pattern.lastIndex = 0
	const matches = pattern.test(value)
	pattern.lastIndex = 0
	return matches
}

/** Recursively copies a value while removing configured secret-bearing fields. */
export function redactSensitive(input: unknown, options: RedactionOptions = {}): unknown {
	const replacement = options.replacement ?? REDACTED_VALUE
	const normalizedKeys = new Set(
		(options.keys ?? DEFAULT_REDACT_KEYS).map((key) => key.toLowerCase())
	)
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
		if (!isPlainObject(value)) return value

		const output: Record<string, unknown> = {}
		for (const [key, nested] of Object.entries(value)) {
			output[key] =
				normalizedKeys.has(key.toLowerCase()) || patternMatches(options.keyPattern, key)
					? replacement
					: visit(nested)
		}
		return output
	}

	return visit(input)
}
