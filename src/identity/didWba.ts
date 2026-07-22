import { principalFromDid, type VerifiedPrincipal } from './principal.js'

const DID_WBA_PREFIX = 'did:wba:'

function invalidDidWba(message: string): Error {
	return new Error(`@goobits/security/identity: ${message}`)
}

function decodeDidWbaComponent(value: string): string {
	try {
		return decodeURIComponent(value)
	} catch {
		throw invalidDidWba('invalid percent encoding')
	}
}

function validateDomain(domain: string): void {
	if (domain.length === 0 || domain.length > 253) {
		throw invalidDidWba('invalid DID-WBA host')
	}
	for (const label of domain.split('.')) {
		if (
			label.length === 0 ||
			label.length > 63 ||
			!/^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/u.test(label)
		) {
			throw invalidDidWba('invalid DID-WBA host')
		}
	}
}

function validateHost(host: string): void {
	const separator = host.lastIndexOf(':')
	const domain = separator === -1 ? host : host.slice(0, separator)
	validateDomain(domain)

	if (separator === -1) return
	if (host.indexOf(':') !== separator) {
		throw invalidDidWba('invalid DID-WBA host')
	}
	const portText = host.slice(separator + 1)
	const port = Number(portText)
	if (!/^\d{1,5}$/u.test(portText) || !Number.isInteger(port) || port < 1 || port > 65_535) {
		throw invalidDidWba('invalid DID-WBA port')
	}
}

function decodePathSegment(value: string): string {
	const segment = decodeDidWbaComponent(value)
	if (
		segment.length === 0 ||
		segment === '.' ||
		segment === '..' ||
		/[\/\\?#\u0000-\u001f\u007f]/u.test(segment)
	) {
		throw invalidDidWba('invalid DID-WBA path')
	}
	return segment
}

/** Machine-readable did:wba verification failure reason. */
export type DidWbaVerificationError =
	| 'missing-header'
	| 'invalid-header'
	| 'invalid-did'
	| 'invalid-timestamp'
	| 'expired'
	| 'domain-mismatch'
	| 'invalid-signature'

/** Parsed did:wba authorization header. */
export interface DidWbaAuthHeader {
	did: string
	nonce: string
	timestamp: string
	verificationMethod: string
	signature: string
}

/** Options for verifying a did:wba authorization header. */
export interface DidWbaVerifyOptions {
	header: string | DidWbaAuthHeader | null | undefined
	expectedDomain?: string
	now?: Date
	maxSkewMs?: number
	verifySignature: (input: DidWbaSignatureInput) => boolean | Promise<boolean>
}

/** Signature payload passed to a did:wba verifier. */
export interface DidWbaSignatureInput {
	did: string
	nonce: string
	timestamp: string
	verificationMethod: string
	signature: string
	message: string
}

/** Result returned after did:wba identity verification. */
export type DidWbaVerificationResult =
	| { ok: true; principal: VerifiedPrincipal; header: DidWbaAuthHeader }
	| { ok: false; reason: DidWbaVerificationError }

/** Builds a did:wba identifier from a domain and optional path. */
export function buildDidWba(domain: string, pathSegments: string[] = [], port?: number): string {
	validateDomain(domain)
	if (port !== undefined && (!Number.isInteger(port) || port < 1 || port > 65_535)) {
		throw invalidDidWba('invalid DID-WBA port')
	}
	const host = port === undefined ? domain : `${domain}%3A${port}`
	const path = pathSegments
		.map((segment) => encodeURIComponent(decodePathSegment(segment)))
		.join(':')
	return `${DID_WBA_PREFIX}${host}${path ? `:${path}` : ''}`
}

/** Resolves a did:wba identifier to its DID document URL. */
export function didWbaToUrl(did: string): string {
	if (!did.startsWith(DID_WBA_PREFIX)) {
		throw invalidDidWba('invalid DID-WBA method')
	}
	const methodId = did.slice(DID_WBA_PREFIX.length)
	const parts = methodId.split(':')
	const [encodedHost, ...encodedPath] = parts
	if (!encodedHost || encodedPath.some((part) => part.length === 0)) {
		throw invalidDidWba('missing DID-WBA host or path segment')
	}
	const host = decodeDidWbaComponent(encodedHost)
	validateHost(host)
	const path = encodedPath.length
		? `/${encodedPath.map((part) => encodeURIComponent(decodePathSegment(part))).join('/')}/did.json`
		: '/.well-known/did.json'
	return `https://${host}${path}`
}

/** Extracts the host domain represented by a did:wba identifier. */
export function didWbaDomain(did: string): string {
	const url = new URL(didWbaToUrl(did))
	return url.host
}

/** Parses a did:wba authorization header into structured fields. */
export function parseDidWbaAuthorizationHeader(
	value: string | null | undefined
): DidWbaAuthHeader | null {
	if (!value) return null
	const trimmed = value.trim()
	const prefix = /^(didwba|did)\s+/i.exec(trimmed)
	if (!prefix) return null
	const params: Record<string, string> = {}
	const raw = trimmed.slice(prefix[0].length)
	const pattern = /\s*([\w-]+)\s*=\s*("[^"]*"|[^,]+)\s*(?:,|$)/g
	let match = pattern.exec(raw)
	while (match) {
		const key = match[1]?.toLowerCase()
		const rawValue = match[2]?.trim()
		if (key && rawValue) {
			params[key] = rawValue.startsWith('"') ? rawValue.slice(1, -1) : rawValue
		}
		match = pattern.exec(raw)
	}

	const did = params['did']
	const nonce = params['nonce']
	const timestamp = params['timestamp']
	const verificationMethod =
		params['verification_method'] ?? params['verification-method'] ?? params['verificationmethod']
	const signature = params['signature']
	if (!did || !nonce || !timestamp || !verificationMethod || !signature) return null
	return { did, nonce, timestamp, verificationMethod, signature }
}

/** Builds the canonical message covered by a did:wba signature. */
export function didWbaSignatureMessage(header: DidWbaAuthHeader): string {
	return `${header.did}\n${header.nonce}\n${header.timestamp}\n${header.verificationMethod}`
}

/** Verifies a did:wba authorization header and returns a principal. */
export async function verifyDidWbaIdentity(
	options: DidWbaVerifyOptions
): Promise<DidWbaVerificationResult> {
	const header =
		typeof options.header === 'string'
			? parseDidWbaAuthorizationHeader(options.header)
			: options.header
	if (!header) {
		return { ok: false, reason: options.header ? 'invalid-header' : 'missing-header' }
	}
	if (!header.did.startsWith(DID_WBA_PREFIX)) {
		return { ok: false, reason: 'invalid-did' }
	}
	let domain: string
	try {
		domain = didWbaDomain(header.did)
	} catch {
		return { ok: false, reason: 'invalid-did' }
	}
	if (options.expectedDomain && domain !== options.expectedDomain) {
		return { ok: false, reason: 'domain-mismatch' }
	}
	const timestamp = Date.parse(header.timestamp)
	if (!Number.isFinite(timestamp)) {
		return { ok: false, reason: 'invalid-timestamp' }
	}
	const now = options.now?.getTime() ?? Date.now()
	const maxSkewMs = options.maxSkewMs ?? 60_000
	if (Math.abs(now - timestamp) > maxSkewMs) {
		return { ok: false, reason: 'expired' }
	}
	const message = didWbaSignatureMessage(header)
	const signatureOk = await options.verifySignature({ ...header, message })
	if (!signatureOk) {
		return { ok: false, reason: 'invalid-signature' }
	}
	return {
		ok: true,
		header,
		principal: principalFromDid(header.did, {
			verificationMethod: header.verificationMethod,
			nonce: header.nonce
		})
	}
}
