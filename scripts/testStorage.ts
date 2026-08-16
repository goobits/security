import { createHash } from 'node:crypto'
import { mkdirSync, realpathSync } from 'node:fs'
import path from 'node:path'

const storageNamePattern = /^[a-z0-9][a-z0-9._-]*$/

const pathContains = (parent: string, candidate: string): boolean => {
	const relativePath = path.relative(parent, candidate)
	return relativePath === '' || (!relativePath.startsWith('..') && !path.isAbsolute(relativePath))
}

const resolveCacheRoot = (projectRoot: string): string => {
	const project = realpathSync.native(path.resolve(projectRoot))
	const configured = process.env.GOOBITS_CACHE_ROOT?.trim()
	if (configured && !path.isAbsolute(configured)) {
		throw new Error(`GOOBITS_CACHE_ROOT must be absolute: ${configured}`)
	}
	const fingerprint = createHash('sha256').update(project).digest('hex').slice(0, 12)
	const configuredRoot = path.resolve(configured || '/temp/frontdesk/goobits')
	mkdirSync(configuredRoot, { recursive: true })
	const cacheRoot = realpathSync.native(configuredRoot)
	const tempRoot = realpathSync.native('/temp')
	if (!pathContains(tempRoot, cacheRoot) || cacheRoot === tempRoot) {
		throw new Error(`GOOBITS_CACHE_ROOT must resolve beneath /temp: ${cacheRoot}`)
	}
	if (pathContains(project, cacheRoot) || pathContains(cacheRoot, project)) {
		throw new Error(`Test cache must be outside and disjoint from the project: ${cacheRoot}`)
	}
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
