/**
 * @goobits/security
 *
 * Server-side security primitives for SvelteKit (and any modern Node-like
 * runtime that exposes Web Crypto on globalThis).
 *
 * Subpath exports are the preferred way to import. Framework-specific and
 * optional-peer integrations are intentionally kept out of this barrel.
 *
 * @module @goobits/security
 */

import packageJson from '../package.json' with { type: 'json' }

/* Logger interface (pluggable). */
export {
	type ConsoleLoggerOptions,
	type LogContext,
	type Logger,
	createConsoleLogger,
	noopLogger
} from './logger.js'

/* Secret-safe logging and audit payloads. */
export {
	type RedactionOptions,
	DEFAULT_REDACT_KEYS,
	isSensitiveKey,
	omitSensitive,
	REDACTED_VALUE,
	redactSensitive
} from './redaction.js'

/* Generic HTTP credential parsing and verification. */
export {
	type ApiKeyVerifierOptions,
	type BasicAuthCredentials,
	type BasicAuthPasswordVerifier,
	type VerifyBasicAuthOptions,
	createApiKey,
	createBasicAuthResponse,
	hashApiKey,
	parseApiKeyHeader,
	parseBasicAuthHeader,
	parseBearerToken,
	verifyApiKey,
	verifyBasicAuthHeader
} from './httpCredentials.js'

/* CSRF protection. */
export {
	type CsrfConfig,
	type CsrfProtection,
	type CsrfTokenStore,
	type GenerateOptions as CsrfGenerateOptions,
	type ValidateOptions as CsrfValidateOptions,
	CSRF_COOKIE_NAME,
	CSRF_HEADER_NAME,
	CSRF_TOKEN_EXPIRY_MS,
	MemoryCsrfStore,
	createCsrf
} from './MemoryCsrfStore.js'
export { type RedisCsrfStoreOptions, type RedisLike, createRedisCsrfStore } from './csrfRedis.js'

/* Content Security Policy. */
export {
	type CspConfig,
	type CspDirective,
	type CspDirectives,
	buildCsp,
	buildCspHeader,
	createCspDirectives,
	createCspNonce
} from './csp.js'

/* reCAPTCHA verification. */
export { type RecaptchaOptions, type RecaptchaResult, verifyRecaptcha } from './recaptcha.js'

/* Cross-runtime crypto and proof helpers. */
export {
	type AesGcmOpenOptions,
	type AesGcmOptions,
	type AesGcmKeyring,
	type AesGcmKeyringConfig,
	type AesGcmKeyringJsonConfig,
	type AesGcmKeyringOpenOptions,
	type AesGcmKeyringSeal,
	type AesGcmKeyringSealOptions,
	type AesGcmSeal,
	type CreateSecurityProofOptions,
	type HmacAlgorithm,
	type HmacSignature,
	type SecurityProof,
	type SecurityProofAlgorithm,
	type SecurityProofVerification,
	type VerifySecurityProofOptions,
	attachSecurityProof,
	base64UrlToBytes,
	bytesToBase64Url,
	bytesToHex,
	bytesToText,
	canonicalizeJson,
	constantTimeEqual,
	createAesGcmKeyring,
	createAesGcmKeyringFromJson,
	createSecurityProof,
	hasAesGcmKey,
	hexToBytes,
	openAesGcm,
	openAesGcmWithKeyring,
	openJson,
	randomBytes,
	randomHex,
	sealAesGcm,
	sealAesGcmWithKeyring,
	sealJson,
	sha256Bytes,
	sha256Hex,
	signHmac,
	textToBytes,
	verifyAttachedSecurityProof,
	verifyHmac,
	verifySecurityProof
} from './crypto/index.js'

/* Decentralized identity adapters. */
export {
	type DidWbaAuthHeader,
	type DidWbaSignatureInput,
	type DidWbaVerificationError,
	type DidWbaVerificationResult,
	type DidWbaVerifyOptions,
	type HttpSignatureHeader,
	type HttpSignatureVerificationError,
	type HttpSignatureVerificationInput,
	type HttpSignatureVerificationResult,
	type IdentityMethod,
	type VerifiedPrincipal,
	type VerifyHttpSignatureOptions,
	buildDidWba,
	didWbaDomain,
	didWbaSignatureMessage,
	didWbaToUrl,
	parseDidWbaAuthorizationHeader,
	parseHttpSignatureHeader,
	principalFromDid,
	principalFromHttpSignature,
	verifyDidWbaIdentity,
	verifyHttpSignatureIdentity
} from './identity/index.js'

/* Rate limiting. */
export {
	type D1RateLimitDatabase,
	type D1RateLimitStoreOptions,
	type GetClientIpOptions,
	type HmacRateLimitStoreOptions,
	type RateLimitConfig,
	type RateLimitEntry,
	type RateLimitResult,
	type RateLimitStore,
	type RateLimitWindow,
	type RateLimiter,
	D1RateLimitStore,
	MemoryRateLimitStore,
	createHmacRateLimitStore,
	createRateLimiter,
	getClientIP
} from './rate-limit/index.js'
export {
	type AuthRateLimitConfig,
	createLoginRateLimiter,
	createPasswordResetRateLimiter,
	createRegistrationRateLimiter
} from './rate-limit/auth.js'

/* Admin authentication. */
export {
	type AuthPrincipal,
	type PrincipalApiKey,
	type PrincipalAuth,
	type PrincipalAuthAlgorithm,
	type PrincipalAuthConfig,
	type PrincipalAuthFailureReason,
	type PrincipalAuthMethod,
	type PrincipalAuthResult,
	createPrincipalAuth
} from './principalAuth.js'
export {
	type AdminAuth,
	type AdminAuthAlgorithm,
	type AdminAuthConfig,
	type AdminAuthResult,
	type AdminUser,
	createAdminAuth,
	generateAdminApiKey
} from './adminAuth.js'

/* Audit logging. */
export {
	type AuditEvent,
	type AuditLogger,
	type AuditOutcome,
	type AuditSink,
	type CreateAuditLoggerOptions,
	createAuditLogger,
	createLoggerSink
} from './audit.js'

/* Security alerting. */
export {
	type Alert,
	type AlertChannel,
	type AlertRule,
	type AlertSeverity,
	type CreateSecurityAlerterOptions,
	type SecurityAlerter,
	type WebhookChannelOptions,
	createSecurityAlerter,
	createWebhookChannel
} from './alerting.js'

/* Lightweight validation helpers. */
export {
	type FieldValidator,
	type ValidationIssue,
	type ValidationIssueCode,
	type ValidationOptions,
	type ValidationResult,
	RequestValidationError,
	validateArray,
	validateBoolean,
	validateNumber,
	validateObject,
	validateRequestBody,
	validateString
} from './validation/simple.js'

/* Version constant. */
/** Security Package Version registry entry for security middleware. */
export const SECURITY_PACKAGE_VERSION = packageJson.version
