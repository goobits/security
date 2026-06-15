import { principalFromDid, type VerifiedPrincipal } from './principal.js'

export type DidWbaVerificationError =
	| 'missing-header'
	| 'invalid-header'
	| 'invalid-did'
	| 'invalid-timestamp'
	| 'expired'
	| 'domain-mismatch'
	| 'invalid-signature'

export interface DidWbaAuthHeader {
	did: string
	nonce: string
	timestamp: string
	verificationMethod: string
	signature: string
}

export interface DidWbaVerifyOptions {
	header: string | DidWbaAuthHeader | null | undefined
	expectedDomain?: string
	now?: Date
	maxSkewMs?: number
	verifySignature: (input: DidWbaSignatureInput) => boolean | Promise<boolean>
}

export interface DidWbaSignatureInput {
	did: string
	nonce: string
	timestamp: string
	verificationMethod: string
	signature: string
	message: string
}

export type DidWbaVerificationResult =
	| { ok: true; principal: VerifiedPrincipal; header: DidWbaAuthHeader }
	| { ok: false; reason: DidWbaVerificationError }

export function buildDidWba(domain: string, pathSegments: string[] = [], port?: number): string {
	if (!domain) {
		throw new Error('@goobits/security/identity: DID-WBA domain is required')
	}
	const host = port ? `${ domain }%3A${ port }` : domain
	const path = pathSegments.map(segment => encodeURIComponent(segment)).join(':')
	return `did:wba:${ host }${ path ? `:${ path }` : '' }`
}

export function didWbaToUrl(did: string): string {
	if (!did.startsWith('did:wba:')) {
		throw new Error('@goobits/security/identity: invalid DID-WBA method')
	}
	const methodId = did.slice('did:wba:'.length)
	const parts = methodId.split(':').filter(Boolean)
	const [ encodedHost, ...encodedPath ] = parts
	if (!encodedHost) {
		throw new Error('@goobits/security/identity: missing DID-WBA host')
	}
	const host = decodeURIComponent(encodedHost)
	const path = encodedPath.length
		? `/${ encodedPath.map(part => decodeURIComponent(part)).join('/') }/did.json`
		: '/.well-known/did.json'
	return `https://${ host }${ path }`
}

export function didWbaDomain(did: string): string {
	const url = new URL(didWbaToUrl(did))
	return url.host
}

export function parseDidWbaAuthorizationHeader(value: string | null | undefined): DidWbaAuthHeader | null {
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

export function didWbaSignatureMessage(header: DidWbaAuthHeader): string {
	return `${ header.did }\n${ header.nonce }\n${ header.timestamp }\n${ header.verificationMethod }`
}

export async function verifyDidWbaIdentity(
	options: DidWbaVerifyOptions
): Promise<DidWbaVerificationResult> {
	const header = typeof options.header === 'string'
		? parseDidWbaAuthorizationHeader(options.header)
		: options.header
	if (!header) {
		return { ok: false, reason: options.header ? 'invalid-header' : 'missing-header' }
	}
	if (!header.did.startsWith('did:wba:')) {
		return { ok: false, reason: 'invalid-did' }
	}
	if (options.expectedDomain && didWbaDomain(header.did) !== options.expectedDomain) {
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
