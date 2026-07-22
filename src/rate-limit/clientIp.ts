/**
 * Options for `getClientIP`. You MUST explicitly opt in to trusting any
 * proxy header  -  otherwise the helper returns the literal `'unknown'`.
 * This default prevents attackers from spoofing identifiers via `x-forwarded-for`
 * when your service is not actually behind a known proxy.
 */
export interface GetClientIpOptions {
	/**
	 * Which proxy headers (if any) to honor. Order is preserved  -  the first
	 * header that's present wins. Default: `[]` (trust none).
	 *
	 * Only enable headers you know your trusted proxy sets, and confirm that
	 * your proxy strips any client-supplied values before adding its own.
	 *
	 * @example `['cf-connecting-ip']` for Cloudflare
	 * @example `['x-forwarded-for']` for AWS ALB / GCP LB (configured to strip)
	 * @example `['x-real-ip']` for Nginx with `proxy_set_header X-Real-IP`
	 */
	trustHeaders?: ReadonlyArray<'cf-connecting-ip' | 'x-forwarded-for' | 'x-real-ip'>
}

function normalizeClientIp(value: string): string | null {
	const candidate = value.trim()
	if (!candidate || candidate.length > 64 || /[\s\u0000-\u001f\u007f]/u.test(candidate)) {
		return null
	}

	if (/^\d{1,3}(?:\.\d{1,3}){3}$/u.test(candidate)) {
		return candidate.split('.').every((part) => Number(part) >= 0 && Number(part) <= 255)
			? candidate
			: null
	}

	if (!candidate.includes(':') || !/^[0-9A-Fa-f:.]+$/u.test(candidate)) return null
	try {
		const parsed = new URL(`http://[${candidate}]/`)
		return parsed.hostname.length > 2 ? candidate : null
	} catch {
		return null
	}
}

/**
 * Resolve the client IP from a Fetch-API `Request`.
 *
 * **By default, this trusts NO proxy headers**  -  it returns `'unknown'` unless
 * you explicitly opt in via `trustHeaders`. This is intentional: blindly
 * trusting `x-forwarded-for` is a common security mistake that turns rate
 * limiters into header-spoofable counters.
 *
 * When running in SvelteKit, prefer `event.getClientAddress()`  -  it consults
 * your platform adapter's trusted proxy config.
 *
 * @example
 * ```ts
 * // Cloudflare deployments:
 * const ip = getClientIP(event.request, { trustHeaders: ['cf-connecting-ip'] })
 *
 * // AWS ALB (configured to strip client-supplied XFF):
 * const ip = getClientIP(event.request, { trustHeaders: ['x-forwarded-for'] })
 *
 * // Direct-internet exposure (NO proxy):
 * // Don't use this helper; rely on event.getClientAddress() or socket.remoteAddress.
 * ```
 */
export function getClientIP(request: Request, options: GetClientIpOptions = {}): string {
	const trustHeaders = options.trustHeaders ?? []

	for (const headerName of trustHeaders) {
		const raw = request.headers.get(headerName)
		if (!raw) continue
		// x-forwarded-for can be a comma-separated chain; the first value is
		// (by convention) the original client.
		const first = raw.split(',')[0]
		if (first) {
			const normalized = normalizeClientIp(first)
			if (normalized) return normalized
		}
	}

	return 'unknown'
}
