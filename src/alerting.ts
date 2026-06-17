/**
 * Security alerting — send notifications when high-priority security events occur.
 *
 * Designed as a thin layer over the audit log: subscribe to specific actions
 * or outcomes, dispatch to a webhook / email / etc. The package does NOT
 * include transport implementations — provide your own `AlertChannel`.
 *
 * @module @goobits/security/alerting
 */

import type { AuditEvent } from './audit.js'
import { type Logger, resolveLogger } from './logger.js'

/** Alert Severity typed model for security alerting. */
export type AlertSeverity = 'info' | 'warning' | 'critical'

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

	return {
		async send(alert: Alert): Promise<void> {
			try {
				const body = transform(alert)
				const response = await fetch(options.url, {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						...(options.headers ?? {})
					},
					body: JSON.stringify(body)
				})
				if (!response.ok) {
					log.error('Webhook alert failed', { status: response.status, title: alert.title })
				}
			} catch(err) {
				log.error('Webhook alert threw', { error: String(err), title: alert.title })
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
				} catch(err) {
					log.error('Alert rule threw', { error: String(err) })
					continue
				}
				if (!candidate) continue

				// Local const removes the need for non-null assertions inside the closure.
				const alert: Alert = candidate
				await Promise.all(
					options.channels.map(channel => channel.send(alert).catch(err => {
						log.error('Alert channel threw', { error: String(err), title: alert.title })
					}))
				)
			}
		}
	}
}
