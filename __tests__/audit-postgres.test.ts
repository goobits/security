import { describe, expect, it, vi } from 'vitest'

import { createPostgresAuditSink } from '../src/audit/postgres.js'

describe('PostgreSQL audit sink', () => {
	it('persists bounded canonical fields and redacts secret-bearing detail', async () => {
		const query = vi.fn(async (_sql: string, _params?: readonly unknown[]) => undefined)
		const sink = createPostgresAuditSink({
			application: 'mail',
			db: { query },
			redactKeys: ['email']
		})

		await sink.record({
			action: 'organization.invitation.create',
			outcome: 'success',
			actorId: 'user-1',
			detail: { email: 'private@example.test', token: 'never-store-me', rowId: 42n },
			error: { name: 'DatabaseError', code: '23505' },
			timestamp: '2026-08-11T12:00:00.000Z'
		})

		expect(query).toHaveBeenCalledOnce()
		const [statement, values] = query.mock.calls[0] ?? []
		expect(statement).toContain('INSERT INTO "security_audit_events"')
		expect(values?.[0]).toBe('mail')
		expect(values?.[1]).toBe('organization.invitation.create')
		expect(values?.[3]).toBe('user-1')
		expect(values?.[12]).toBe(JSON.stringify({ email: '[redacted]', token: '[redacted]', rowId: '42' }))
		expect(values?.[14]).toBe('23505')
		expect(values?.join(' ')).not.toContain('never-store-me')
	})

	it('rejects unsafe configuration and propagates storage failures safely', async () => {
		expect(() =>
			createPostgresAuditSink({
				application: 'mail',
				db: { query: async () => undefined },
				tableName: 'audit; DROP TABLE users'
			})
		).toThrow(/invalid PostgreSQL audit table/)
		expect(() => createPostgresAuditSink({ application: '', db: { query: async () => undefined } })).toThrow(
			/application/
		)

		const logger = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() }
		const sink = createPostgresAuditSink({
			application: 'dashboard',
			db: { query: async () => Promise.reject(new Error('private database error')) },
			logger
		})
		await expect(
			sink.record({ action: 'test', outcome: 'error', timestamp: new Date().toISOString() })
		).rejects.toThrow('private database error')
		expect(logger.error).toHaveBeenCalledWith(
			expect.any(String),
			expect.not.objectContaining({ error: 'private database error' })
		)
	})

	it('bounds scalar fields and truncates oversized detail', async () => {
		const query = vi.fn(async (_sql: string, _params?: readonly unknown[]) => undefined)
		const sink = createPostgresAuditSink({
			application: 'dashboard',
			db: { query },
			maxDetailBytes: 256,
			maxFieldLength: 64
		})

		await sink.record({
			action: 'x'.repeat(100),
			outcome: 'success',
			detail: { value: 'y'.repeat(300) },
			timestamp: '2026-08-11T12:00:00.000Z'
		})

		const values = query.mock.calls[0]?.[1]
		expect(values?.[1]).toBe('x'.repeat(64))
		expect(values?.[12]).toBe(JSON.stringify({ truncated: true }))
	})
})
