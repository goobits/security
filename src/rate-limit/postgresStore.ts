import type { RateLimitEntry, RateLimitStore } from './types.js'

/** Minimal PostgreSQL query contract used by `PostgresRateLimitStore`. */
export interface PostgresRateLimitDatabase {
	query<T = Record<string, unknown>>(
		sql: string,
		params?: readonly unknown[]
	): Promise<{ rows: T[] }>
}

/** Configures the PostgreSQL rate-limit table. */
export interface PostgresRateLimitStoreOptions {
	/** Shared table name. Default: `rate_limits`. */
	table?: string
}

type PostgresRateLimitRow = {
	timestamps: unknown
	expires_at_ms: number | string | null
}

function quotePostgresIdentifier(identifier: string): string {
	if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(identifier)) {
		throw new Error(`PostgresRateLimitStore: invalid SQL identifier "${identifier}"`)
	}
	return `"${identifier}"`
}

function parseTimestamps(value: unknown): number[] | null {
	let parsed = value
	if (typeof parsed === 'string') {
		try {
			parsed = JSON.parse(parsed) as unknown
		} catch {
			return null
		}
	}
	if (
		!Array.isArray(parsed) ||
		!parsed.every((timestamp) => typeof timestamp === 'number' && Number.isFinite(timestamp))
	) {
		return null
	}
	return parsed
}

/**
 * Returns idempotent PostgreSQL schema SQL for a shared sliding-window store.
 *
 * Apply this during the owning application's normal migration/bootstrap step.
 */
export function postgresRateLimitSchemaSql(
	options: PostgresRateLimitStoreOptions = {}
): string {
	const tableName = options.table ?? 'rate_limits'
	const table = quotePostgresIdentifier(tableName)
	const expiresAtIndex = quotePostgresIdentifier(`${tableName}_expires_at_idx`)
	return `
CREATE TABLE IF NOT EXISTS ${table} (
	key TEXT PRIMARY KEY,
	timestamps JSONB NOT NULL,
	expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS ${expiresAtIndex}
	ON ${table}(expires_at);
`
}

/**
 * PostgreSQL-backed sliding-window rate-limit store.
 *
 * Each increment is one atomic upsert, so multiple application processes share
 * one bounded counter without a read-modify-write race.
 */
export class PostgresRateLimitStore implements RateLimitStore {
	private readonly table: string

	constructor(
		private readonly db: PostgresRateLimitDatabase,
		options: PostgresRateLimitStoreOptions = {}
	) {
		this.table = quotePostgresIdentifier(options.table ?? 'rate_limits')
	}

	async getEntry(key: string): Promise<RateLimitEntry | null> {
		const result = await this.db.query<PostgresRateLimitRow>(
			`SELECT
				timestamps,
				EXTRACT(EPOCH FROM expires_at) * 1000 AS expires_at_ms
			 FROM ${this.table}
			 WHERE key = $1
			 LIMIT 1`,
			[key]
		)
		const row = result.rows[0]
		if (!row) return null
		const expiresAtMs = Number(row.expires_at_ms)
		const timestamps = parseTimestamps(row.timestamps)
		if (timestamps && Number.isFinite(expiresAtMs) && expiresAtMs > Date.now()) {
			return { timestamps }
		}
		await this.deleteEntry(key)
		return null
	}

	async incrementEntry(
		key: string,
		timestamp: number,
		ttlMs: number,
		maxEntries?: number
	): Promise<RateLimitEntry> {
		const cutoff = timestamp - ttlMs
		const retainedLimit = maxEntries === undefined ? null : Math.max(0, maxEntries - 1)
		const result = await this.db.query<PostgresRateLimitRow>(
			`INSERT INTO ${this.table} AS current_entry (key, timestamps, expires_at)
			 VALUES (
				$1,
				jsonb_build_array($2::double precision),
				to_timestamp(($2::double precision + $3::double precision) / 1000)
			 )
			 ON CONFLICT (key) DO UPDATE SET
				timestamps = COALESCE(
					(
						SELECT jsonb_agg(retained.value ORDER BY retained.ordinality)
						FROM (
							SELECT item.value, item.ordinality
							FROM jsonb_array_elements(
								CASE
									WHEN current_entry.expires_at <= to_timestamp($2::double precision / 1000)
										THEN '[]'::jsonb
									WHEN jsonb_typeof(current_entry.timestamps) = 'array'
										THEN current_entry.timestamps
									ELSE '[]'::jsonb
								END
							) WITH ORDINALITY AS item(value, ordinality)
							WHERE jsonb_typeof(item.value) = 'number'
								AND (item.value #>> '{}')::double precision > $4::double precision
							ORDER BY item.ordinality DESC
							LIMIT $5
						) AS retained
					),
					'[]'::jsonb
				) || jsonb_build_array($2::double precision),
				expires_at = to_timestamp(
					($2::double precision + $3::double precision) / 1000
				)
			 RETURNING
				timestamps,
				EXTRACT(EPOCH FROM expires_at) * 1000 AS expires_at_ms`,
			[key, timestamp, ttlMs, cutoff, retainedLimit]
		)
		const timestamps = parseTimestamps(result.rows[0]?.timestamps)
		if (!timestamps) {
			throw new Error('PostgresRateLimitStore: increment did not return a valid entry')
		}
		return { timestamps }
	}

	async deleteEntry(key: string): Promise<void> {
		await this.db.query(`DELETE FROM ${this.table} WHERE key = $1`, [key])
	}
}
