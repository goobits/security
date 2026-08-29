/**
 * Reports a detached failure without changing the caller's availability policy.
 *
 * @param message - Stable operation context for the reported failure.
 * @param cause - Original error or rejection reason.
 */
export function reportDetachedError(message: string, cause: unknown): void {
	const error = new Error(message, { cause })
	const runtimeReporter = Reflect.get(globalThis, 'reportError')
	if (typeof runtimeReporter === 'function') {
		Reflect.apply(runtimeReporter, globalThis, [ error ])
		return
	}
	console.error(error)
}
