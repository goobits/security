/** Identity method attached to a verified principal. */
export type IdentityMethod = 'jwt' | 'api-key' | 'did-wba' | 'http-signature' | (string & {})

/** Principal identity returned after authentication verification. */
export interface VerifiedPrincipal {
	id: string
	method: IdentityMethod
	claims?: Record<string, unknown>
}

/** Creates a verified principal from a did:wba identifier. */
export function principalFromDid(
	did: string,
	claims: Record<string, unknown> = {}
): VerifiedPrincipal {
	return {
		id: did,
		method: 'did-wba',
		claims
	}
}

/** Creates a verified principal from an HTTP Signature key ID. */
export function principalFromHttpSignature(
	keyId: string,
	claims: Record<string, unknown> = {}
): VerifiedPrincipal {
	return {
		id: keyId,
		method: 'http-signature',
		claims
	}
}
