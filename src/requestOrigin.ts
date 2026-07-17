/** Framework-agnostic browser request-origin verification. */

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])
const ALLOWED_FETCH_SITES = new Set(['same-origin', 'same-site', 'none'])
const MAX_ORIGIN_HEADER_LENGTH = 2_048

/** Machine-readable request-origin rejection reasons. */
export type RequestOriginFailureReason =
	| 'cross-site'
	| 'invalid-origin'
	| 'origin-mismatch'
	| 'invalid-referer'
	| 'referer-mismatch'
	| 'missing-browser-context'

/** Result of checking one browser mutation against an explicit origin set. */
export type RequestOriginResult = { ok: true } | { ok: false; reason: RequestOriginFailureReason }

/** Inputs for strict browser mutation origin verification. */
export interface VerifyRequestOriginOptions {
	request: Request
	requestUrl: URL
	allowedOrigins: Iterable<string>
	/** Explicitly permit clients that send neither Origin nor Referer. Default: false. */
	allowMissingBrowserContext?: boolean
}

function parseOrigin(value: string): string | null {
	if (!value || value.length > MAX_ORIGIN_HEADER_LENGTH || /[\u0000-\u001f\u007f]/u.test(value)) {
		return null
	}
	try {
		const parsed = new URL(value)
		return parsed.protocol === 'http:' || parsed.protocol === 'https:' ? parsed.origin : null
	} catch {
		return null
	}
}

function normalizeAllowedOrigins(values: Iterable<string>): Set<string> {
	const origins = new Set<string>()
	for (const value of values) {
		const origin = parseOrigin(value)
		if (origin) origins.add(origin)
	}
	return origins
}

/** Verifies Fetch Metadata, Origin, and Referer for an unsafe browser request. */
export function verifyRequestOrigin({
	request,
	requestUrl,
	allowedOrigins,
	allowMissingBrowserContext = false
}: VerifyRequestOriginOptions): RequestOriginResult {
	if (SAFE_METHODS.has(request.method.toUpperCase())) return { ok: true }

	const fetchSite = request.headers.get('sec-fetch-site')?.toLowerCase()
	if (fetchSite && !ALLOWED_FETCH_SITES.has(fetchSite)) {
		return { ok: false, reason: 'cross-site' }
	}

	const allowed = normalizeAllowedOrigins(allowedOrigins)
	allowed.add(requestUrl.origin)

	const originHeader = request.headers.get('origin')
	if (originHeader) {
		const origin = parseOrigin(originHeader)
		if (!origin) return { ok: false, reason: 'invalid-origin' }
		if (!allowed.has(origin)) return { ok: false, reason: 'origin-mismatch' }
	}

	const refererHeader = request.headers.get('referer')
	if (refererHeader) {
		const refererOrigin = parseOrigin(refererHeader)
		if (!refererOrigin) return { ok: false, reason: 'invalid-referer' }
		if (!allowed.has(refererOrigin)) return { ok: false, reason: 'referer-mismatch' }
	}

	if (!originHeader && !refererHeader && !allowMissingBrowserContext) {
		return { ok: false, reason: 'missing-browser-context' }
	}

	return { ok: true }
}
