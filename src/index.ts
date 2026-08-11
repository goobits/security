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

export { isProductionRuntime, readRuntimeEnv } from './runtime.js'

/* Logger interface (pluggable). */
export {
	type ConsoleLoggerOptions,
	type LogContext,
	type Logger,
	createConsoleLogger,
	noopLogger,
	safeErrorContext
} from './logger.js'

/* Secret-safe logging and audit payloads. */
export {
	type RedactionOptions,
	DEFAULT_REDACT_KEYS,
	isSensitiveKey,
	omitSensitive,
	REDACTED_VALUE,
	redactSecretText,
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
	type CsrfGenerateOptions,
	type MemoryCsrfStoreOptions,
	type CsrfValidateOptions,
	CSRF_COOKIE_NAME,
	CSRF_HEADER_NAME,
	CSRF_TOKEN_EXPIRY_MS,
	MemoryCsrfStore,
	createCsrf
} from './csrf.js'
export {
	BodyTooLargeError,
	type ReadBodyOptions,
	readAsyncIterableBytes,
	readFormDataBody,
	readJsonBody,
	readRequestBodyBytes
} from './requestBody.js'
export {
	type RequestOriginFailureReason,
	type RequestOriginResult,
	type VerifyRequestOriginOptions,
	verifyRequestOrigin
} from './requestOrigin.js'
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
	base64ToBytes,
	bytesToBase64,
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
	parseAesGcmKeyringSeal,
	parseAesGcmSeal,
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
	type PrincipalIdentity,
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
	type MemoryRateLimitStoreOptions,
	type PostgresRateLimitDatabase,
	type PostgresRateLimitStoreOptions,
	type RateLimitConfig,
	type RateLimitEntry,
	type RateLimitResult,
	type RateLimitStore,
	type RateLimitWindow,
	type RateLimiter,
	type ResilientRateLimitStoreOptions,
	D1RateLimitStore,
	MemoryRateLimitStore,
	PostgresRateLimitStore,
	createHmacRateLimitStore,
	createPostgresRateLimitSchemaSql,
	createRateLimiter,
	createResilientRateLimitStore,
	getClientIP,
	postgresRateLimitSchemaSql
} from './rate-limit/index.js'
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
	type JwksSignatureAlgorithm,
	type JwtHmacAlgorithm,
	type JwtVerification,
	type SignJwtOptions,
	type VerifyJwtOptions,
	type VerifyJwtWithJwksOptions,
	signJwt,
	verifyJwt,
	verifyJwtWithJwks
} from './jwt.js'
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
export { type D1AuditDatabase, type D1AuditSinkOptions, createD1AuditSink } from './audit/d1.js'
export { type PostgresAuditDatabase, type PostgresAuditSinkOptions, createPostgresAuditSink } from './audit/postgres.js'

/* Security alerting. */
export {
	type Alert,
	type AlertChannel,
	type AlertRule,
	type AlertSeverity,
	type CreateSecurityAlerterOptions,
	type SecurityAlerter,
	type ThresholdAlert,
	type ThresholdAlertObserverOptions,
	type ThresholdAlertRule,
	type WebhookChannelOptions,
	createSecurityAlerter,
	createThresholdAlertObserver,
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
