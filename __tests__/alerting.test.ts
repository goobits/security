import { afterEach, describe, expect, it, vi } from 'vitest'

import { type AlertChannel, createSecurityAlerter, createWebhookChannel } from '../src/alerting.js'
import type { AuditEvent } from '../src/audit.js'

afterEach(() => {
	vi.useRealTimers()
	vi.unstubAllGlobals()
})

function event(partial: Partial<AuditEvent>): AuditEvent {
	return {
		action: 'test.action',
		outcome: 'success',
		timestamp: '2026-01-01T00:00:00.000Z',
		...partial
	}
}

describe('createSecurityAlerter', () => {
	it('dispatches an alert through every channel when a rule matches', async () => {
		const channel1Sends: unknown[] = []
		const channel2Sends: unknown[] = []
		const ch1: AlertChannel = {
			async send(a) {
				channel1Sends.push(a)
			}
		}
		const ch2: AlertChannel = {
			async send(a) {
				channel2Sends.push(a)
			}
		}

		const alerter = createSecurityAlerter({
			channels: [ch1, ch2],
			rules: [
				(e) =>
					e.outcome === 'denied'
						? {
								severity: 'critical',
								title: 'Denied',
								message: e.action,
								source: 'test',
								timestamp: e.timestamp
							}
						: null
			]
		})

		await alerter.process(event({ outcome: 'denied' }))

		expect(channel1Sends).toHaveLength(1)
		expect(channel2Sends).toHaveLength(1)
	})

	it('skips dispatch when no rule matches', async () => {
		const sends: unknown[] = []
		const ch: AlertChannel = {
			async send(a) {
				sends.push(a)
			}
		}

		const alerter = createSecurityAlerter({
			channels: [ch],
			rules: [() => null]
		})

		await alerter.process(event({}))
		expect(sends).toHaveLength(0)
	})

	it('continues when a rule throws', async () => {
		const sends: unknown[] = []
		const ch: AlertChannel = {
			async send(a) {
				sends.push(a)
			}
		}

		const alerter = createSecurityAlerter({
			channels: [ch],
			rules: [
				() => {
					throw new Error('rule boom')
				},
				() => ({ severity: 'info', title: 'Hi', message: 'm', source: 'test', timestamp: 'now' })
			]
		})

		await expect(alerter.process(event({}))).resolves.not.toThrow()
		expect(sends).toHaveLength(1)
	})

	it('continues when a channel throws', async () => {
		const sends: unknown[] = []
		const okChannel: AlertChannel = {
			async send(a) {
				sends.push(a)
			}
		}
		const badChannel: AlertChannel = {
			async send() {
				throw new Error('channel boom')
			}
		}

		const alerter = createSecurityAlerter({
			channels: [badChannel, okChannel],
			rules: [
				() => ({ severity: 'info', title: 'Hi', message: 'm', source: 'test', timestamp: 'now' })
			]
		})

		await expect(alerter.process(event({}))).resolves.not.toThrow()
		expect(sends).toHaveLength(1)
	})
})

describe('createWebhookChannel', () => {
	it('POSTs JSON to the configured URL', async () => {
		const fetched: Array<{ url: string; init: RequestInit }> = []
		vi.stubGlobal(
			'fetch',
			vi.fn(async (url: unknown, init: unknown) => {
				fetched.push({ url: String(url), init: init as RequestInit })
				return { ok: true, status: 200 } as unknown as Response
			})
		)

		const channel = createWebhookChannel({ url: 'https://hook.test/alerts' })
		await channel.send({
			severity: 'critical',
			title: 'T',
			message: 'm',
			source: 'test',
			timestamp: 'now'
		})

		expect(fetched).toHaveLength(1)
		expect(fetched[0]?.url).toBe('https://hook.test/alerts')
		expect(fetched[0]?.init.method).toBe('POST')
		expect(JSON.parse(String(fetched[0]?.init.body)).title).toBe('T')
	})

	it('applies transform when provided', async () => {
		const fetched: Array<{ body: unknown }> = []
		vi.stubGlobal(
			'fetch',
			vi.fn(async (_url: unknown, init: unknown) => {
				fetched.push({ body: JSON.parse(String((init as RequestInit).body)) })
				return { ok: true, status: 200 } as unknown as Response
			})
		)

		const channel = createWebhookChannel({
			url: 'https://hook.test',
			transform: (a) => ({ text: `[${a.severity}] ${a.title}` })
		})

		await channel.send({
			severity: 'warning',
			title: 'Hi',
			message: 'm',
			source: 'test',
			timestamp: 'now'
		})

		expect(fetched[0]?.body).toEqual({ text: '[warning] Hi' })
	})

	it('aborts webhook delivery after the configured timeout', async () => {
		vi.useFakeTimers()
		let signal: AbortSignal | undefined
		vi.stubGlobal(
			'fetch',
			vi.fn(
				async (_url: unknown, init: unknown) =>
					new Promise<Response>((_resolve, reject) => {
						signal = (init as RequestInit).signal ?? undefined
						signal?.addEventListener('abort', () =>
							reject(new DOMException('Aborted', 'AbortError'))
						)
					})
			)
		)
		const logger = {
			debug: vi.fn(),
			info: vi.fn(),
			warn: vi.fn(),
			error: vi.fn()
		}
		const channel = createWebhookChannel({
			url: 'https://hook.test',
			timeoutMs: 25,
			logger
		})
		const sending = channel.send({
			severity: 'warning',
			title: 'Slow webhook',
			message: 'm',
			source: 'test',
			timestamp: 'now'
		})

		await vi.advanceTimersByTimeAsync(25)
		await expect(sending).resolves.toBeUndefined()
		expect(signal?.aborted).toBe(true)
		expect(logger.error).toHaveBeenCalledWith(
			'Webhook alert threw',
			expect.objectContaining({ title: 'Slow webhook' })
		)
	})

	it('rejects invalid webhook timeouts at configuration time', () => {
		expect(() => createWebhookChannel({ url: 'https://hook.test', timeoutMs: 0 })).toThrow(
			'Webhook timeoutMs must be a positive finite number'
		)
		expect(() => createWebhookChannel({ url: 'https://hook.test', timeoutMs: Number.NaN })).toThrow(
			'Webhook timeoutMs must be a positive finite number'
		)
	})
})
