import { describe, expect, it, vi } from 'vitest'

import { createD1AuditSink } from '../src/audit/d1.js'

describe('D1 audit sink', () => {
	it('persists canonical fields and redacts secret-bearing detail', async () => {
		const run = vi.fn(async () => undefined)
		const bind = vi.fn((..._values: unknown[]) => ({ run }))
		const prepare = vi.fn(() => ({ bind }))
		const sink = createD1AuditSink({ db: { prepare } })

		await sink.record({
			action: 'admin.user_granted',
			outcome: 'success',
			actorId: '42',
			detail: { password: 'never-store-me', role: 'admin' },
			timestamp: '2026-07-15T12:00:00.000Z'
		})

		expect(prepare).toHaveBeenCalledWith(expect.stringContaining('security_audit_events'))
		const values = bind.mock.calls[0] ?? []
		expect(values[0]).toBe('admin.user_granted')
		expect(values[2]).toBe('42')
		expect(values[11]).toBe(JSON.stringify({ password: '[redacted]', role: 'admin' }))
		expect(values.join(' ')).not.toContain('never-store-me')
		expect(run).toHaveBeenCalledOnce()
	})

	it('rejects unsafe table names and propagates storage failures safely', async () => {
		expect(() =>
			createD1AuditSink({
				db: { prepare: () => ({ bind: () => ({ run: async () => undefined }) }) },
				tableName: 'audit; DROP TABLE users'
			})
		).toThrow(/invalid D1 audit table/)

		const logger = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() }
		const sink = createD1AuditSink({
			db: {
				prepare: () => ({
					bind: () => ({ run: async () => Promise.reject(new Error('private database error')) })
				})
			},
			logger
		})
		await expect(
			sink.record({ action: 'test', outcome: 'error', timestamp: new Date().toISOString() })
		).rejects.toThrow('private database error')
		expect(logger.error).toHaveBeenCalledWith(
			expect.any(String),
			expect.objectContaining({ error_type: 'Error' })
		)
		expect(logger.error).toHaveBeenCalledWith(
			expect.any(String),
			expect.not.objectContaining({ error: 'private database error' })
		)
	})

	it('supports application PII redaction and serializes bigint detail safely', async () => {
		const run = vi.fn(async () => undefined)
		const bind = vi.fn((..._values: unknown[]) => ({ run }))
		const sink = createD1AuditSink({
			db: { prepare: () => ({ bind }) },
			redactKeys: ['email', 'invite_code']
		})

		await sink.record({
			action: 'admin.invite_create',
			outcome: 'success',
			detail: {
				email: 'private@example.test',
				inviteCode: 'private-code',
				password: 'still-default-redacted',
				rowId: 42n
			},
			error: { name: 'DatabaseError' },
			timestamp: '2026-07-15T12:00:00.000Z'
		})

		expect(bind.mock.calls[0]?.[11]).toBe(
			JSON.stringify({
				email: '[redacted]',
				inviteCode: '[redacted]',
				password: '[redacted]',
				rowId: '42'
			})
		)
		expect(bind.mock.calls[0]?.[13]).toBeNull()
		expect(run).toHaveBeenCalledOnce()
	})

	it('bounds scalar fields and never stores error messages', async () => {
		const bind = vi.fn((..._values: unknown[]) => ({ run: async () => undefined }))
		const sink = createD1AuditSink({
			db: { prepare: () => ({ bind }) },
			maxFieldLength: 64
		})

		await sink.record({
			action: 'x'.repeat(100),
			outcome: 'error',
			error: { name: 'DatabaseError' },
			timestamp: '2026-07-15T12:00:00.000Z'
		})

		expect(bind.mock.calls[0]?.[0]).toBe('x'.repeat(64))
		expect(bind.mock.calls[0]?.[13]).toBeNull()
	})
})
