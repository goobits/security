export type IdentityMethod = 'jwt' | 'api-key' | 'did-wba' | 'http-signature' | (string & {})

export interface VerifiedPrincipal {
	id: string
	method: IdentityMethod
	claims?: Record<string, unknown>
}

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
