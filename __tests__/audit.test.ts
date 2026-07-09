import { describe, expect, it, vi } from 'vitest'

import { type AuditEvent, type AuditSink, createAuditLogger, createLoggerSink } from '../src/audit.js'
import { withAudit } from '../src/audit/sveltekit.js'
import type { Logger } from '../src/logger.js'

function makeSink(): { sink: AuditSink; records: AuditEvent[] } {
	const records: AuditEvent[] = []
	return {
		sink: { record(event) { records.push(event) } },
		records
	}
}

describe('createAuditLogger', () => {
	it('writes events to the sink with auto-generated timestamp', async () => {
		const { sink, records } = makeSink()
		const auditor = createAuditLogger({ sink })

		await auditor.log({ action: 'test.action', outcome: 'success' })

		expect(records).toHaveLength(1)
		expect(records[0]?.action).toBe('test.action')
		expect(records[0]?.outcome).toBe('success')
		expect(records[0]?.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/)
	})

	it('respects caller-supplied timestamp', async () => {
		const { sink, records } = makeSink()
		const auditor = createAuditLogger({ sink })

		const replayTs = '2020-01-01T00:00:00.000Z'
		await auditor.log({ action: 'replay.action', outcome: 'success', timestamp: replayTs })

		expect(records[0]?.timestamp).toBe(replayTs)
	})

	it('catches sink errors and continues', async () => {
		const errors: string[] = []
		const log: Logger = {
			debug() {}, info() {}, warn() {},
			error(msg) { errors.push(msg) }
		}
		const auditor = createAuditLogger({
			logger: log,
			sink: { record() { throw new Error('sink boom') } }
		})

		await expect(auditor.log({ action: 'x', outcome: 'success' })).resolves.not.toThrow()
		expect(errors.length).toBeGreaterThan(0)
	})
})

describe('createLoggerSink', () => {
	it('emits audit events via Logger.info', () => {
		const info = vi.fn()
		const log: Logger = { debug() {}, info, warn() {}, error() {} }
		const sink = createLoggerSink(log)

		sink.record({
			action: 'user.login',
			outcome: 'success',
			timestamp: '2026-01-01T00:00:00.000Z'
		})

		expect(info).toHaveBeenCalledTimes(1)
		expect(info).toHaveBeenCalledWith('audit:user.login', expect.objectContaining({
			action: 'user.login',
			outcome: 'success'
		}))
	})
})

describe('withAudit redaction', () => {
	function makeEvent(method: string, body: object): { event: unknown } {
		const request = new Request('https://example.test/api', {
			method,
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(body)
		})
		return {
			event: {
				request,
				url: new URL('https://example.test/api'),
				params: {},
				locals: {},
				cookies: {},
				fetch: globalThis.fetch,
				getClientAddress: () => '127.0.0.1',
				platform: undefined,
				route: { id: null },
				setHeaders: () => {},
				isDataRequest: false,
				isSubRequest: false
			}
		}
	}

	it('redacts default sensitive keys from request body', async () => {
		const { sink, records } = makeSink()
		const auditor = createAuditLogger({ sink })

		const handler = withAudit(
			{ action: 'user.login', auditor, includeRequestBody: true },
			async () => new Response('OK')
		)

		const { event } = makeEvent('POST', { email: 'a@b.com', password: 'secret123', token: 'abc' })
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		await handler(event as any)

		// Audit is fire-and-forget; flush the async logger microtask.
		await Promise.resolve()

		expect(records).toHaveLength(1)
		const body = records[0]?.detail?.['requestBody'] as Record<string, unknown>
		expect(body['email']).toBe('a@b.com')
		expect(body['password']).toBe('[redacted]')
		expect(body['token']).toBe('[redacted]')
	})

	it('redacts nested sensitive keys from request body', async () => {
		const { sink, records } = makeSink()
		const auditor = createAuditLogger({ sink })

		const handler = withAudit(
			{ action: 'user.login', auditor, includeRequestBody: true },
			async () => new Response('OK')
		)

		const { event } = makeEvent('POST', {
			profile: {
				email: 'a@b.com',
				credentials: {
					password: 'secret123'
				}
			},
			tokens: [
				{ token: 'abc' }
			]
		})
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		await handler(event as any)
		await Promise.resolve()

		const body = records[0]?.detail?.['requestBody'] as {
			profile: { credentials: { password: string } }
			tokens: Array<{ token: string }>
		}
		expect(body.profile.credentials.password).toBe('[redacted]')
		expect(body.tokens[0]?.token).toBe('[redacted]')
	})

	it('honors empty redactKeys (no redaction) when explicitly opted out', async () => {
		const { sink, records } = makeSink()
		const auditor = createAuditLogger({ sink })

		const handler = withAudit(
			{ action: 'user.login', auditor, includeRequestBody: true, redactKeys: [] },
			async () => new Response('OK')
		)

		const { event } = makeEvent('POST', { password: 'plaintext' })
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		await handler(event as any)
		await Promise.resolve()

		const body = records[0]?.detail?.['requestBody'] as Record<string, unknown>
		expect(body['password']).toBe('plaintext')
	})

	it('derives outcome from response status', async () => {
		const { sink, records } = makeSink()
		const auditor = createAuditLogger({ sink })

		const handler = withAudit(
			{ action: 'admin.action', auditor },
			async () => new Response('forbidden', { status: 403 })
		)

		const { event } = makeEvent('POST', {})
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		await handler(event as any)
		await Promise.resolve()

		expect(records[0]?.outcome).toBe('denied')
		expect(records[0]?.status).toBe(403)
	})
})
