import path from 'node:path'

import { resolveManagedStorageRoot } from './managedStorageRoot.ts'

const storageNamePattern = /^[a-z0-9][a-z0-9._-]*$/

const resolveCacheRoot = (projectRoot: string): string => {
	const { cacheRoot, fingerprint } = resolveManagedStorageRoot(projectRoot)
	return path.join(cacheRoot, 'build-storage', fingerprint)
}

const resolveTestStorage = (projectRoot: string, kind: 'artifacts' | 'cache', name: string) => {
	if (!storageNamePattern.test(name)) {
		throw new Error(`Test storage name must match ${storageNamePattern}: ${name}`)
	}
	return path.join(resolveCacheRoot(projectRoot), 'build', 'tests', kind, name)
}

export const resolveViteCacheDirectory = (projectRoot: string): string =>
	resolveTestStorage(projectRoot, 'cache', 'vite')

export const resolveTestArtifactDirectory = (projectRoot: string, name: string): string =>
	resolveTestStorage(projectRoot, 'artifacts', name)
