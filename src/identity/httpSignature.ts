import { principalFromHttpSignature, type VerifiedPrincipal } from './principal.js'

export type HttpSignatureVerificationError =
	| 'missing-header'
	| 'invalid-header'
	| 'invalid-signature'

export interface HttpSignatureHeader {
	keyId: string
	algorithm?: string
	headers?: string[]
	signature: string
}

export interface VerifyHttpSignatureOptions {
	header: string | HttpSignatureHeader | null | undefined
	message: string
	verifySignature: (input: HttpSignatureVerificationInput) => boolean | Promise<boolean>
}

export interface HttpSignatureVerificationInput extends HttpSignatureHeader {
	message: string
}

export type HttpSignatureVerificationResult =
	| { ok: true; principal: VerifiedPrincipal; header: HttpSignatureHeader }
	| { ok: false; reason: HttpSignatureVerificationError }

export function parseHttpSignatureHeader(value: string | null | undefined): HttpSignatureHeader | null {
	if (!value) return null
	const params: Record<string, string> = {}
	const pattern = /\s*([\w-]+)\s*=\s*("[^"]*"|[^,]+)\s*(?:,|$)/g
	let match = pattern.exec(value)
	while (match) {
		const key = match[1]
		const rawValue = match[2]?.trim()
		if (key && rawValue) {
			params[key.toLowerCase()] = rawValue.startsWith('"') ? rawValue.slice(1, -1) : rawValue
		}
		match = pattern.exec(value)
	}
	const keyId = params['keyid']
	const signature = params['signature']
	if (!keyId || !signature) return null
	return {
		keyId,
		signature,
		...(params['algorithm'] ? { algorithm: params['algorithm'] } : {}),
		...(params['headers'] ? { headers: params['headers'].split(/\s+/u).filter(Boolean) } : {})
	}
}

export async function verifyHttpSignatureIdentity(
	options: VerifyHttpSignatureOptions
): Promise<HttpSignatureVerificationResult> {
	const header = typeof options.header === 'string'
		? parseHttpSignatureHeader(options.header)
		: options.header
	if (!header) {
		return { ok: false, reason: options.header ? 'invalid-header' : 'missing-header' }
	}
	if (!(await options.verifySignature({ ...header, message: options.message }))) {
		return { ok: false, reason: 'invalid-signature' }
	}
	return {
		ok: true,
		header,
		principal: principalFromHttpSignature(header.keyId, {
			algorithm: header.algorithm,
			headers: header.headers
		})
	}
}
