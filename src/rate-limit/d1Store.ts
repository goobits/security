import type { RateLimitEntry, RateLimitStore } from './types.js'

/** Minimal Cloudflare D1-compatible database shape used by `D1RateLimitStore`. */
export interface D1RateLimitDatabase {
	prepare(sql: string): {
		bind(...args: unknown[]): {
			first<T = Record<string, unknown>>(): Promise<T | null>
			run(): Promise<unknown>
		}
	}
}

export interface D1RateLimitStoreOptions {
	table?: string
	columns?: Partial<{
		key: string
		count: string
		resetAt: string
	}>
}

const DEFAULT_D1_RATE_LIMIT_COLUMNS = {
	key: 'key',
	count: 'count',
	resetAt: 'reset_at'
} as const
type D1RateLimitColumns = {
	key: string
	count: string
	resetAt: string
}

function quoteD1Identifier(identifier: string): string {
	if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(identifier)) {
		throw new Error(`D1RateLimitStore: invalid SQL identifier "${identifier}"`)
	}
	return `"${identifier}"`
}

/**
 * D1-backed rate limit store.
 *
 * Uses the common `rate_limits(key, count, reset_at)` table by default. The
 * `count` column stores JSON timestamp arrays for sliding-window precision.
 */
export class D1RateLimitStore implements RateLimitStore {
	private readonly table: string
	private readonly columns: D1RateLimitColumns

	constructor(
		private readonly db: D1RateLimitDatabase,
		options: D1RateLimitStoreOptions = {}
	) {
		this.table = quoteD1Identifier(options.table ?? 'rate_limits')
		this.columns = {
			...DEFAULT_D1_RATE_LIMIT_COLUMNS,
			...options.columns
		}
		for (const column of Object.values(this.columns)) quoteD1Identifier(column)
	}

	private mapEntry(
		row: { count: number | string | null; reset_at: number | string | null } | null,
		now = Date.now()
	): RateLimitEntry | null {
		if (!row) return null
		const resetAtMs = Number(row.reset_at ?? 0) * 1000
		if (!Number.isFinite(resetAtMs) || resetAtMs <= now) return null

		const raw = row.count
		if (typeof raw === 'string') {
			try {
				const parsed = JSON.parse(raw) as unknown
				if (
					Array.isArray(parsed) &&
					parsed.every((value) => typeof value === 'number' && Number.isFinite(value))
				) {
					return { timestamps: parsed }
				}
			} catch {
				return null
			}
		}

		return null
	}

	async getEntry(key: string): Promise<RateLimitEntry | null> {
		const keyColumn = quoteD1Identifier(this.columns.key)
		const countColumn = quoteD1Identifier(this.columns.count)
		const resetAtColumn = quoteD1Identifier(this.columns.resetAt)
		const row = await this.db
			.prepare(
				`SELECT ${countColumn} AS count, ${resetAtColumn} AS reset_at
				 FROM ${this.table}
				 WHERE ${keyColumn} = ? LIMIT 1`
			)
			.bind(key)
			.first<{ count: number | string | null; reset_at: number | string | null }>()
		const entry = this.mapEntry(row)
		if (!row || entry) return entry
		await this.deleteEntry(key)
		return null
	}

	async incrementEntry(
		key: string,
		timestamp: number,
		ttlMs: number,
		maxEntries?: number
	): Promise<RateLimitEntry> {
		const keyColumn = quoteD1Identifier(this.columns.key)
		const countColumn = quoteD1Identifier(this.columns.count)
		const resetAtColumn = quoteD1Identifier(this.columns.resetAt)
		const cutoff = timestamp - ttlMs
		const retainedLimit = maxEntries === undefined ? -1 : Math.max(0, maxEntries - 1)
		const resetAtSeconds = Math.ceil((timestamp + ttlMs) / 1000)
		const row = await this.db
			.prepare(
				`INSERT INTO ${this.table} (${keyColumn}, ${countColumn}, ${resetAtColumn})
				 VALUES (?, json_array(?), ?)
				 ON CONFLICT(${keyColumn}) DO UPDATE SET
					${countColumn} = json_insert(
						(
							SELECT json_group_array(value)
							FROM (
								SELECT value, position
								FROM (
									SELECT CAST(value AS INTEGER) AS value, CAST(key AS INTEGER) AS position
									FROM json_each(
										CASE
											WHEN CAST(${this.table}.${resetAtColumn} AS INTEGER) * 1000 <= ? THEN json_array()
											WHEN json_valid(${this.table}.${countColumn}) AND json_type(${this.table}.${countColumn}) = 'array'
												THEN ${this.table}.${countColumn}
											ELSE json_array()
										END
									)
									WHERE CAST(value AS REAL) > ?
									ORDER BY position DESC
									LIMIT ?
								)
								ORDER BY position
							)
						),
						'$[#]',
						?
					),
					${resetAtColumn} = excluded.${resetAtColumn}
				 RETURNING ${countColumn} AS count, ${resetAtColumn} AS reset_at`
			)
			.bind(key, timestamp, resetAtSeconds, timestamp, cutoff, retainedLimit, timestamp)
			.first<{ count: number | string | null; reset_at: number | string | null }>()
		const entry = this.mapEntry(row, timestamp)
		if (!entry) throw new Error('D1RateLimitStore: increment did not return a valid entry')
		return entry
	}

	async deleteEntry(key: string): Promise<void> {
		const keyColumn = quoteD1Identifier(this.columns.key)
		await this.db.prepare(`DELETE FROM ${this.table} WHERE ${keyColumn} = ?`).bind(key).run()
	}
}
