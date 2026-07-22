/**
 * Security alerting  -  send notifications when high-priority security events occur.
 *
 * Designed as a thin layer over the audit log: subscribe to specific actions
 * or outcomes, dispatch to a webhook / email / etc. The package does NOT
 * include transport implementations  -  provide your own `AlertChannel`.
 *
 * @module @goobits/security/alerting
 */

import type { AuditEvent } from './audit.js'
import { resolveLogger } from './_internal/resolveLogger.js'
import type { Logger } from './logger.js'
import { MemoryRateLimitStore, type RateLimitStore } from './rate-limit/index.js'

/** Alert Severity typed model for security alerting. */
export type AlertSeverity = 'info' | 'warning' | 'critical'

/** An event counter rule used to emit at most one alert per fixed window bucket. */
export interface ThresholdAlertRule<
	EventName extends string = string,
	Severity extends AlertSeverity = AlertSeverity
> {
	eventName: EventName
	max: number
	windowMs: number
	severity: Severity
}

/** Alert emitted when a named event reaches a configured threshold. */
export interface ThresholdAlert<
	EventName extends string = string,
	Severity extends AlertSeverity = AlertSeverity
> {
	type: 'threshold_exceeded'
	eventName: EventName
	severity: Severity
	count: number
	windowMs: number
	timestamp: string
}

/** Configuration for the generic, store-backed threshold observer. */
export interface ThresholdAlertObserverOptions<
	EventName extends string = string,
	Severity extends AlertSeverity = AlertSeverity
> {
	rules: ReadonlyArray<ThresholdAlertRule<EventName, Severity>>
	onAlert?: (alert: ThresholdAlert<EventName, Severity>) => Promise<void> | void
	store?: RateLimitStore
	keyPrefix?: string
	/** Injectable clock for deterministic consumers and tests. Default: `Date.now`. */
	now?: () => number
}

function assertThresholdRule(rule: ThresholdAlertRule): void {
	if (!rule.eventName) throw new Error('Threshold alert eventName is required')
	if (!Number.isSafeInteger(rule.max) || rule.max <= 0) {
		throw new RangeError('Threshold alert max must be a positive safe integer')
	}
	if (!Number.isSafeInteger(rule.windowMs) || rule.windowMs <= 0) {
		throw new RangeError('Threshold alert windowMs must be a positive safe integer')
	}
}

/**
 * Counts named events in a sliding window and claims one notification per
 * fixed window bucket. A shared store makes both counters and claims atomic
 * across application instances; the default memory store is single-process.
 */
export function createThresholdAlertObserver<
	EventName extends string,
	Severity extends AlertSeverity = AlertSeverity
>({
	rules,
	onAlert,
	store = new MemoryRateLimitStore(),
	keyPrefix = 'security-alert',
	now = Date.now
}: ThresholdAlertObserverOptions<EventName, Severity>): (event: {
	name: EventName
}) => Promise<void> {
	for (const rule of rules) assertThresholdRule(rule)

	return async (event): Promise<void> => {
		for (const rule of rules) {
			if (event.name !== rule.eventName) continue
			const timestamp = now()
			const key = `${keyPrefix}:${rule.eventName}:${rule.max}:${rule.windowMs}:${rule.severity}`
			const entry = await store.incrementEntry(key, timestamp, rule.windowMs, rule.max + 1)
			const cutoff = timestamp - rule.windowMs
			const count = entry.timestamps.filter((value) => value > cutoff).length
			if (count < rule.max || !onAlert) continue

			const bucket = Math.floor(timestamp / rule.windowMs)
			const claim = await store.incrementEntry(
				`${key}:notification:${bucket}`,
				timestamp,
				rule.windowMs,
				2
			)
			const claimCount = claim.timestamps.filter((value) => value > cutoff).length
			if (claimCount !== 1) continue

			await onAlert({
				type: 'threshold_exceeded',
				eventName: rule.eventName,
				severity: rule.severity,
				count,
				windowMs: rule.windowMs,
				timestamp: new Date(timestamp).toISOString()
			})
		}
	}
}

/** Alert request or option shape for security alerting. */
export interface Alert {
	severity: AlertSeverity
	title: string
	message: string
	/** Free-form source identifier. Recommended convention: `'<package>/<module>'` (e.g. `'goobits/security'`, `'my-app/payments'`). */
	source: string
	timestamp: string
	context?: Record<string, unknown>
}

/** Alert Channel request or option shape for security alerting. */
export interface AlertChannel {
	send(alert: Alert): Promise<void>
}

/** Webhook Channel Options request or option shape for security alerting. */
export interface WebhookChannelOptions {
	url: string
	headers?: Record<string, string>
	/** Network timeout in milliseconds. Default: 5000. */
	timeoutMs?: number
	/** Custom JSON body shape. Default: passes the `Alert` as-is. */
	transform?(alert: Alert): unknown
	logger?: Logger
}

/**
 * Build a webhook-based `AlertChannel` (HTTP POST with JSON body).
 *
 * @example
 * ```ts
 * const slack = createWebhookChannel({
 *   url: process.env.SLACK_WEBHOOK_URL!,
 *   transform: a => ({ text: `[${ a.severity.toUpperCase() }] ${ a.title }\n${ a.message }` })
 * })
 * ```
 */
export function createWebhookChannel(options: WebhookChannelOptions): AlertChannel {
	const log = resolveLogger(options.logger)
	const transform = options.transform ?? ((alert: Alert) => alert)
	const timeoutMs = options.timeoutMs ?? 5000
	if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
		throw new RangeError('Webhook timeoutMs must be a positive finite number')
	}

	return {
		async send(alert: Alert): Promise<void> {
			const controller = new AbortController()
			const timeout = setTimeout(() => controller.abort(), timeoutMs)
			try {
				const body = transform(alert)
				const response = await fetch(options.url, {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						...(options.headers ?? {})
					},
					body: JSON.stringify(body),
					signal: controller.signal
				})
				if (!response.ok) {
					log.error('Webhook alert failed', { status: response.status, title: alert.title })
				}
			} catch (err) {
				log.error('Webhook alert threw', { error: String(err), title: alert.title })
			} finally {
				clearTimeout(timeout)
			}
		}
	}
}

/** Alert Rule typed model for security alerting. */
export type AlertRule = (event: AuditEvent) => Alert | null

/** Create Security Alerter Options request or option shape for security alerting. */
export interface CreateSecurityAlerterOptions {
	channels: AlertChannel[]
	rules: AlertRule[]
	logger?: Logger
}

/** Security Alerter request or option shape for security alerting. */
export interface SecurityAlerter {
	/**
	 * Inspect an audit event; if any rule matches, dispatch an alert through
	 * every configured channel.
	 */
	process(event: AuditEvent): Promise<void>
}

/**
 * Combine alert channels + rules into a single dispatcher.
 *
 * @example
 * ```ts
 * const alerter = createSecurityAlerter({
 *   channels: [ slack, email ],
 *   rules: [
 *     // Critical: any admin route returning 403
 *     (e) => e.action.startsWith('admin.') && e.outcome === 'denied'
 *       ? { severity: 'critical', title: 'Admin access denied', message: e.action, source: 'goobits/security', timestamp: e.timestamp, context: e as unknown as Record<string, unknown> }
 *       : null
 *   ]
 * })
 *
 * // Connect to the audit logger:
 * const auditor = createAuditLogger({
 *   sink: {
 *     async record(e) {
 *       await myDatabaseSink.record(e)
 *       await alerter.process(e)
 *     }
 *   }
 * })
 * ```
 */
export function createSecurityAlerter(options: CreateSecurityAlerterOptions): SecurityAlerter {
	const log = resolveLogger(options.logger)

	return {
		async process(event: AuditEvent): Promise<void> {
			for (const rule of options.rules) {
				let candidate: Alert | null
				try {
					candidate = rule(event)
				} catch (err) {
					log.error('Alert rule threw', { error: String(err) })
					continue
				}
				if (!candidate) continue

				// Local const removes the need for non-null assertions inside the closure.
				const alert: Alert = candidate
				await Promise.all(
					options.channels.map((channel) =>
						channel.send(alert).catch((err) => {
							log.error('Alert channel threw', { error: String(err), title: alert.title })
						})
					)
				)
			}
		}
	}
}
