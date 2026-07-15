import { noopLogger, type Logger } from '../logger.js'

/** Resolves an optional logger without exposing package-internal wiring publicly. */
export function resolveLogger(logger: Logger | undefined): Logger {
	return logger ?? noopLogger
}
