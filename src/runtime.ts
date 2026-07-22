import { readEnv } from './_internal/env.js'

/** Returns false only for explicit development and test modes, keeping unknown runtimes safe. */
export function isProductionRuntime(): boolean {
	const mode = readEnv('NODE_ENV')
	return mode !== 'development' && mode !== 'test'
}
