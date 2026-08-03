import { signHmac, type HmacAlgorithm, verifyHmac } from './signatures.js'

/** @deprecated Import `HmacAlgorithm` from `@goobits/security/crypto` instead. */
export type SecurityProofAlgorithm = HmacAlgorithm

/** HMAC-backed proof bound to a JSON-compatible payload. */
export interface SecurityProof {
	type: 'SecurityProof'
	algorithm: HmacAlgorithm
	created: string
	verificationMethod: string
	proofPurpose: string
	proofValue: string
	domain?: string
	challenge?: string
}

/** Options for creating a security proof. */
export interface CreateSecurityProofOptions {
	secret: Uint8Array | string
	verificationMethod: string
	proofPurpose?: string
	algorithm?: HmacAlgorithm
	created?: string
	domain?: string
	challenge?: string
}

/** Options for verifying a security proof. */
export interface VerifySecurityProofOptions {
	secret: Uint8Array | string
	domain?: string
	challenge?: string
	proofPurpose?: string
	verificationMethod?: string
	now?: Date
	maxAgeMs?: number
}

/** Verification result for a security proof. */
export interface SecurityProofVerification {
	ok: boolean
	reason?:
		| 'domain-mismatch'
		| 'challenge-mismatch'
		| 'purpose-mismatch'
		| 'verification-method-mismatch'
		| 'expired'
		| 'invalid-created'
		| 'invalid-signature'
}

type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue }

function toJsonValue(value: unknown): JsonValue {
	if (value === null) return null
	if (['boolean', 'string'].includes(typeof value)) return value as boolean | string
	if (typeof value === 'number') {
		if (!Number.isFinite(value)) {
			throw new Error('@goobits/security/crypto: proof payload numbers must be finite')
		}
		return value
	}
	if (Array.isArray(value)) {
		return value.map(toJsonValue)
	}
	if (typeof value === 'object') {
		const out: { [key: string]: JsonValue } = {}
		for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
			if (entry !== undefined) {
				out[key] = toJsonValue(entry)
			}
		}
		return out
	}
	throw new Error('@goobits/security/crypto: proof payload must be JSON-compatible')
}

/** Canonicalizes JSON-compatible values for proof signing. */
export function canonicalizeJson(value: unknown): string {
	const json = toJsonValue(value)
	if (json === null || typeof json !== 'object') return JSON.stringify(json)
	if (Array.isArray(json)) {
		return `[${json.map(canonicalizeJson).join(',')}]`
	}
	return `{${Object.keys(json)
		.sort()
		.map((key) => `${JSON.stringify(key)}:${canonicalizeJson(json[key])}`)
		.join(',')}}`
}

function proofMetadata(proof: SecurityProof): Omit<SecurityProof, 'proofValue'> {
	const { proofValue: _proofValue, ...metadata } = proof
	return metadata
}

function proofMessage(payload: unknown, proof: SecurityProof): string {
	return canonicalizeJson({
		payload,
		proof: proofMetadata(proof)
	})
}

/** Creates a detached HMAC security proof for a payload. */
export async function createSecurityProof(
	payload: unknown,
	options: CreateSecurityProofOptions
): Promise<SecurityProof> {
	const proof: SecurityProof = {
		type: 'SecurityProof',
		algorithm: options.algorithm ?? 'HS256',
		created: options.created ?? new Date().toISOString(),
		verificationMethod: options.verificationMethod,
		proofPurpose: options.proofPurpose ?? 'assertionMethod',
		proofValue: '',
		...(options.domain ? { domain: options.domain } : {}),
		...(options.challenge ? { challenge: options.challenge } : {})
	}
	const signature = await signHmac(proofMessage(payload, proof), options.secret, proof.algorithm)
	return {
		...proof,
		proofValue: signature.value
	}
}

/** Verifies a detached HMAC security proof for a payload. */
export async function verifySecurityProof(
	payload: unknown,
	proof: SecurityProof,
	options: VerifySecurityProofOptions
): Promise<SecurityProofVerification> {
	if (options.domain !== undefined && proof.domain !== options.domain) {
		return { ok: false, reason: 'domain-mismatch' }
	}
	if (options.challenge !== undefined && proof.challenge !== options.challenge) {
		return { ok: false, reason: 'challenge-mismatch' }
	}
	if (options.proofPurpose !== undefined && proof.proofPurpose !== options.proofPurpose) {
		return { ok: false, reason: 'purpose-mismatch' }
	}
	if (
		options.verificationMethod !== undefined &&
		proof.verificationMethod !== options.verificationMethod
	) {
		return { ok: false, reason: 'verification-method-mismatch' }
	}
	if (options.maxAgeMs !== undefined) {
		const createdAt = Date.parse(proof.created)
		if (!Number.isFinite(createdAt)) {
			return { ok: false, reason: 'invalid-created' }
		}
		if ((options.now ?? new Date()).getTime() - createdAt > options.maxAgeMs) {
			return { ok: false, reason: 'expired' }
		}
	}
	const ok = await verifyHmac(
		proofMessage(payload, proof),
		{ algorithm: proof.algorithm, value: proof.proofValue },
		options.secret
	)
	return ok ? { ok: true } : { ok: false, reason: 'invalid-signature' }
}

/** Attaches a security proof to a record payload. */
export async function attachSecurityProof<T extends Record<string, unknown>>(
	payload: T,
	options: CreateSecurityProofOptions
): Promise<T & { proof: SecurityProof }> {
	const { proof: _existingProof, ...unsignedPayload } = payload
	const proof = await createSecurityProof(unsignedPayload, options)
	return {
		...unsignedPayload,
		proof
	} as T & { proof: SecurityProof }
}

/** Verifies a security proof attached to a record payload. */
export async function verifyAttachedSecurityProof(
	payload: Record<string, unknown> & { proof?: SecurityProof },
	options: VerifySecurityProofOptions
): Promise<SecurityProofVerification> {
	const { proof, ...unsignedPayload } = payload
	if (!proof) {
		return { ok: false, reason: 'invalid-signature' }
	}
	return verifySecurityProof(unsignedPayload, proof, options)
}
