/**
 * Cross-runtime environment helpers with production-safe unknown-mode semantics.
 *
 * Runtimes without `process.env` return no values and are treated as production
 * for security defaults. Applications should pass deployment bindings directly
 * when their runtime does not expose Node-compatible environment variables.
 *
 * @module @goobits/security/runtime
 */

interface ProcessLike {
	env?: Record<string, string | undefined>
}

function readProcess(): ProcessLike | undefined {
	return (globalThis as unknown as { process?: ProcessLike }).process
}

/** Reads a non-empty Node-compatible environment variable when available. */
export function readRuntimeEnv(name: string): string | undefined {
	const value = readProcess()?.env?.[name]
	return value && value.length > 0 ? value : undefined
}

/**
 * Returns false only for an explicitly declared development or test runtime.
 * Unknown runtimes therefore retain production-safe cookies and bypass rules.
 */
export function isProductionRuntime(mode?: string): boolean {
	const resolvedMode = arguments.length === 0 ? readRuntimeEnv('NODE_ENV') : mode
	return resolvedMode !== 'development' && resolvedMode !== 'test'
}
