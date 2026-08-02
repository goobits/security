/**
 * Pluggable logger interface.
 *
 * Every module in `@goobits/security` that emits diagnostic output accepts a
 * `Logger` via its options object. Consumers can supply any object matching
 * this shape  -  `@goobits/logger`, `pino`, `winston`, `console`, or a no-op.
 *
 * By design, this package has zero hard dependency on any specific logging
 * library. The default for every factory is `noopLogger` (silent).
 *
 * @module @goobits/security/logger
 */

export type LogContext = Record<string, unknown>

/** Logger request or option shape for security middleware. */
export interface Logger {
	debug(message: string, context?: LogContext): void
	info(message: string, context?: LogContext): void
	warn(message: string, context?: LogContext): void
	error(message: string, context?: LogContext): void
}

/** Projects an arbitrary thrown value without retaining messages or stacks. */
export function safeErrorContext(error: unknown): LogContext {
	if (!(error instanceof Error)) return { errorType: typeof error }
	const errorName = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/u.test(error.name) ? error.name : 'Error'
	return { errorType: errorName }
}

/**
 * A logger that swallows every call. Default for all factories.
 *
 * Use this in production code paths where you intentionally don't want
 * any output, or in tests where you want to suppress noise.
 */
export const noopLogger: Logger = {
	debug(): void {},
	info(): void {},
	warn(): void {},
	error(): void {}
}

/** Console Logger Options request or option shape for security middleware. */
export interface ConsoleLoggerOptions {
	/** A prefix added before every log line, e.g. `[security:csrf]`. */
	prefix?: string
	/** Minimum level to emit. Default: `'info'`. */
	level?: 'debug' | 'info' | 'warn' | 'error'
}

const LEVEL_ORDER: Record<NonNullable<ConsoleLoggerOptions['level']>, number> = {
	debug: 0,
	info: 1,
	warn: 2,
	error: 3
}

/**
 * Create a logger that writes to `console.{debug,info,warn,error}`.
 *
 * Intended as a sensible default when consumers don't have their own logger.
 * For real applications, plug in your own logger of choice.
 *
 * @example
 * ```ts
 * import { createConsoleLogger } from '@goobits/security/logger'
 * const log = createConsoleLogger({ prefix: '[my-app]', level: 'warn' })
 * ```
 */
export function createConsoleLogger(options: ConsoleLoggerOptions = {}): Logger {
	const { prefix, level = 'info' } = options
	const minLevel = LEVEL_ORDER[level]
	const tag = prefix ? `${prefix} ` : ''

	const emit = (
		method: 'debug' | 'info' | 'warn' | 'error',
		message: string,
		context?: LogContext
	): void => {
		if (LEVEL_ORDER[method] < minLevel) return
		if (context) {
			// eslint-disable-next-line no-console
			console[method](`${tag}${message}`, context)
		} else {
			// eslint-disable-next-line no-console
			console[method](`${tag}${message}`)
		}
	}

	return {
		debug: (msg, ctx): void => emit('debug', msg, ctx),
		info: (msg, ctx): void => emit('info', msg, ctx),
		warn: (msg, ctx): void => emit('warn', msg, ctx),
		error: (msg, ctx): void => emit('error', msg, ctx)
	}
}
