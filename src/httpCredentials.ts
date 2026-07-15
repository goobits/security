import {
	bytesToHex,
	constantTimeEqual,
	randomBytes,
	signHmac,
	textToBytes
} from './crypto/index.js'

const MAX_AUTHORIZATION_HEADER_LENGTH = 8_192
const MAX_BASIC_USERNAME_LENGTH = 256
const MAX_BASIC_PASSWORD_LENGTH = 4_096
const API_KEY_VERIFIER_PREFIX = 'hmac-sha256:'

/** Parsed HTTP Basic credentials. */
export interface BasicAuthCredentials {
	username: string
	password: string
}

/** Verifies a submitted password against a stored password hash. */
export type BasicAuthPasswordVerifier = (storedHash: string, password: string) => Promise<boolean>

/** Inputs for constant-work HTTP Basic verification. */
export interface VerifyBasicAuthOptions {
	authHeader: string | null
	getPasswordHash: (
		username: string
	) => string | null | undefined | Promise<string | null | undefined>
	verifyPassword: BasicAuthPasswordVerifier
	dummyPasswordHash?: string
}

/** Inputs for creating or checking a server-side API-key verifier. */
export interface ApiKeyVerifierOptions {
	secret: Uint8Array | string
	context?: string
}

function parseAuthorizationScheme(
	value: string | null,
	allowedSchemes: ReadonlySet<string>
): string | null {
	if (!value || value.length > MAX_AUTHORIZATION_HEADER_LENGTH) return null
	const match = /^([A-Za-z][A-Za-z0-9_-]*)[ \t]+([^\s]+)$/.exec(value.trim())
	if (!match) return null
	const scheme = match[1]?.toLowerCase()
	const credential = match[2]
	return scheme && credential && allowedSchemes.has(scheme) ? credential : null
}

/** Extracts a strict Bearer credential. Raw header values are never accepted. */
export function parseBearerToken(value: string | null): string | null {
	return parseAuthorizationScheme(value, new Set(['bearer']))
}

/** Extracts an explicit ApiKey or Bearer credential without accepting raw values. */
export function parseApiKeyHeader(value: string | null): string | null {
	return parseAuthorizationScheme(value, new Set(['apikey', 'bearer']))
}

function decodeBasicCredential(value: string): string | null {
	try {
		const binary = atob(value)
		const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0))
		return new TextDecoder('utf-8', { fatal: true }).decode(bytes)
	} catch {
		return null
	}
}

/** Parses a bounded HTTP Basic Authorization header. */
export function parseBasicAuthHeader(authHeader: string | null): BasicAuthCredentials | null {
	const encoded = parseAuthorizationScheme(authHeader, new Set(['basic']))
	if (!encoded) return null
	const decoded = decodeBasicCredential(encoded)
	if (!decoded) return null

	const separatorIndex = decoded.indexOf(':')
	if (separatorIndex <= 0) return null
	const username = decoded.slice(0, separatorIndex)
	const password = decoded.slice(separatorIndex + 1)
	if (
		!password ||
		username.length > MAX_BASIC_USERNAME_LENGTH ||
		password.length > MAX_BASIC_PASSWORD_LENGTH
	) {
		return null
	}
	return { username, password }
}

/** Verifies HTTP Basic credentials and optionally performs a dummy hash check for unknown users. */
export async function verifyBasicAuthHeader({
	authHeader,
	getPasswordHash,
	verifyPassword,
	dummyPasswordHash
}: VerifyBasicAuthOptions): Promise<string | null> {
	const credentials = parseBasicAuthHeader(authHeader)
	if (!credentials) return null

	const storedHash = await getPasswordHash(credentials.username)
	if (!storedHash) {
		if (dummyPasswordHash) await verifyPassword(dummyPasswordHash, credentials.password)
		return null
	}
	return (await verifyPassword(storedHash, credentials.password)) ? credentials.username : null
}

function sanitizeBasicAuthRealm(realm: string): string {
	return realm
		.replace(/[\u0000-\u001f\u007f]/g, '')
		.replaceAll('\\', '\\\\')
		.replaceAll('"', '\\"')
}

/** Creates a standards-compliant HTTP Basic challenge response. */
export function createBasicAuthResponse({
	realm = 'Authentication Required',
	body = 'Unauthorized'
}: { realm?: string; body?: BodyInit } = {}): Response {
	return new Response(body, {
		status: 401,
		headers: { 'WWW-Authenticate': `Basic realm="${sanitizeBasicAuthRealm(realm)}"` }
	})
}

/** Creates a cryptographically random API key with an optional visible prefix. */
export function createApiKey({
	prefix = 'key',
	bytes = 32
}: { prefix?: string; bytes?: number } = {}): string {
	if (!/^[A-Za-z][A-Za-z0-9_-]{0,31}$/.test(prefix)) {
		throw new Error('@goobits/security/http-credentials: invalid API-key prefix')
	}
	if (!Number.isSafeInteger(bytes) || bytes < 16 || bytes > 128) {
		throw new Error('@goobits/security/http-credentials: bytes must be an integer from 16 to 128')
	}
	return `${prefix}_${bytesToHex(randomBytes(bytes))}`
}

function assertApiKeyVerifierSecret(secret: Uint8Array | string): void {
	const length = typeof secret === 'string' ? textToBytes(secret).byteLength : secret.byteLength
	if (length < 32) {
		throw new Error('@goobits/security/http-credentials: verifier secret must be at least 32 bytes')
	}
}

/** Derives a non-reversible, server-secret-bound API-key verifier. */
export async function hashApiKey(
	apiKey: string,
	{ secret, context = 'api-key:v1' }: ApiKeyVerifierOptions
): Promise<string> {
	if (!apiKey) throw new Error('@goobits/security/http-credentials: apiKey is required')
	if (!context) throw new Error('@goobits/security/http-credentials: context is required')
	assertApiKeyVerifierSecret(secret)
	const signature = await signHmac(`${context}\0${apiKey}`, secret, 'HS256')
	return `${API_KEY_VERIFIER_PREFIX}${signature.value}`
}

/** Checks an API key against a server-secret-bound verifier in constant time. */
export async function verifyApiKey(
	apiKey: string,
	verifier: string,
	options: ApiKeyVerifierOptions
): Promise<boolean> {
	if (!apiKey || !verifier.startsWith(API_KEY_VERIFIER_PREFIX)) return false
	const candidate = await hashApiKey(apiKey, options)
	return constantTimeEqual(candidate, verifier)
}
