import {
	lstatSync,
	mkdtempSync,
	readlinkSync,
	realpathSync,
	rmSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import { ensureManagedBuildOutput } from '../scripts/managedBuildOutput.ts'
import { resolveManagedStorageRoot } from '../scripts/managedStorageRoot.ts'

const temporaryDirectories: string[] = []

function makeTemporaryDirectory(name: string): string {
	const directory = mkdtempSync(path.join(tmpdir(), name))
	temporaryDirectories.push(directory)
	return directory
}

afterEach(() => {
	for (const directory of temporaryDirectories.splice(0)) {
		rmSync(directory, { force: true, recursive: true })
	}
})

describe('managed storage', () => {
	it('uses the operating-system temporary directory by default', () => {
		const projectRoot = makeTemporaryDirectory('security-storage-project-')

		const { cacheRoot, fingerprint } = resolveManagedStorageRoot(projectRoot, {})

		expect(cacheRoot).toBe(path.join(realpathSync.native(tmpdir()), 'goobits'))
		expect(fingerprint).toMatch(/^[a-f0-9]{12}$/)
	})

	it('accepts an absolute cache root outside the project', () => {
		const projectRoot = makeTemporaryDirectory('security-storage-project-')
		const cacheRoot = makeTemporaryDirectory('security-storage-cache-')

		const resolved = resolveManagedStorageRoot(projectRoot, { GOOBITS_CACHE_ROOT: cacheRoot })

		expect(resolved.cacheRoot).toBe(realpathSync.native(cacheRoot))
	})

	it('rejects relative and project-contained cache roots', () => {
		const projectRoot = makeTemporaryDirectory('security-storage-project-')

		expect(() =>
			resolveManagedStorageRoot(projectRoot, { GOOBITS_CACHE_ROOT: 'relative/cache' })
		).toThrow('GOOBITS_CACHE_ROOT must be absolute')
		expect(() =>
			resolveManagedStorageRoot(projectRoot, {
				GOOBITS_CACHE_ROOT: path.join(projectRoot, 'cache')
			})
		).toThrow('Managed storage must be outside and disjoint from the project')
	})

	it('links build output to managed external storage', () => {
		const projectRoot = makeTemporaryDirectory('security-storage-project-')
		const cacheRoot = makeTemporaryDirectory('security-storage-cache-')
		const previousCacheRoot = process.env.GOOBITS_CACHE_ROOT
		process.env.GOOBITS_CACHE_ROOT = cacheRoot

		try {
			const output = ensureManagedBuildOutput(projectRoot, 'dist')
			const target = realpathSync.native(path.resolve(path.dirname(output), readlinkSync(output)))

			expect(lstatSync(output).isSymbolicLink()).toBe(true)
			expect(target.startsWith(`${realpathSync.native(cacheRoot)}${path.sep}`)).toBe(true)
		} finally {
			if (previousCacheRoot === undefined) delete process.env.GOOBITS_CACHE_ROOT
			else process.env.GOOBITS_CACHE_ROOT = previousCacheRoot
		}
	})
})
