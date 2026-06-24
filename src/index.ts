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
	createCsrf
} from './csrf.js'
export {
	type RedisCsrfStoreOptions,
	type RedisLike,
	createRedisCsrfStore
} from './csrf-redis.js'

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
export {
	type RecaptchaOptions,
	type RecaptchaResult,
	verifyRecaptcha,
	verifyRecaptchaToken
} from './recaptcha.js'

/* Rate limiting. */
export {
	type GetClientIpOptions,
	type RateLimitConfig,
	type RateLimitEntry,
	type RateLimitResult,
	type RateLimitStore,
	type RateLimitWindow,
	type RateLimiter,
	MemoryRateLimitStore,
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
	type AdminAuth,
	type AdminAuthAlgorithm,
	type AdminAuthConfig,
	type AdminAuthResult,
	type AdminUser,
	createAdminAuth,
	generateAdminApiKey
} from './admin-auth.js'

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

/* Version constant. */
export const SECURITY_PACKAGE_VERSION = packageJson.version
