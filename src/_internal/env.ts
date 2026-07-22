/**
 * Cross-runtime environment helpers.
 *
 * Centralizes the "is `process.env` even there?" guard used by multiple
 * modules. Works on Node, Bun, Deno (via `Deno.env` shim is NOT included
 * here  -  pass values explicitly when running on Deno), and Cloudflare
 * Workers (where `process.env` is absent  -  every call returns undefined,
 * which forces the consumer to pass values explicitly).
 *
 * @internal
 */

interface ProcessLike {
	env?: Record<string, string | undefined>
}

function readProcess(): ProcessLike | undefined {
	return (globalThis as unknown as { process?: ProcessLike }).process
}

/**
 * Read an env var. Returns `undefined` when:
 *  - `process` is not on `globalThis` (Workers, browser, some Deno modes)
 *  - The variable is unset
 *  - The variable is empty string
 */
export function readEnv(name: string): string | undefined {
	const value = readProcess()?.env?.[name]
	return value && value.length > 0 ? value : undefined
}
