import { createHash } from 'node:crypto'
import {
	cpSync,
	existsSync,
	lstatSync,
	mkdirSync,
	readFileSync,
	readlinkSync,
	realpathSync,
	rmSync,
	symlinkSync,
	writeFileSync
} from 'node:fs'
import path from 'node:path'

const outputNamePattern = /^[a-z0-9][a-z0-9._-]*$/

function pathContains(parent, candidate) {
	const relativePath = path.relative(parent, candidate)
	return relativePath === '' || (!relativePath.startsWith('..') && !path.isAbsolute(relativePath))
}

function resolveManagedBuildOutput(projectRoot, name) {
	if (!outputNamePattern.test(name)) throw new Error(`Managed output name is invalid: ${name}`)
	const project = realpathSync.native(path.resolve(projectRoot))
	const configured = process.env.GOOBITS_CACHE_ROOT?.trim() || '/temp/frontdesk/goobits'
	if (!path.isAbsolute(configured)) throw new Error(`GOOBITS_CACHE_ROOT must be absolute: ${configured}`)

	mkdirSync(configured, { recursive: true })
	const cacheRoot = realpathSync.native(configured)
	const tempRoot = realpathSync.native('/temp')
	if (cacheRoot === tempRoot || !pathContains(tempRoot, cacheRoot)) {
		throw new Error(`GOOBITS_CACHE_ROOT must resolve beneath /temp: ${cacheRoot}`)
	}
	if (pathContains(project, cacheRoot) || pathContains(cacheRoot, project)) {
		throw new Error(`Build storage must be disjoint from the project: ${cacheRoot}`)
	}

	const fingerprint = createHash('sha256').update(project).digest('hex').slice(0, 12)
	const target = path.join(cacheRoot, 'build-storage', fingerprint, 'build', 'outputs', name)
	const output = path.join(project, name)
	const packState = path.join(path.dirname(target), `.${name}.pack-state`)
	mkdirSync(target, { recursive: true })
	return { output, packState, target }
}

export function ensureManagedBuildOutput(projectRoot, name) {
	const { output, target } = resolveManagedBuildOutput(projectRoot, name)

	try {
		const details = lstatSync(output)
		if (!details.isSymbolicLink()) {
			throw new Error(`Workspace-local build output must be migrated before use: ${output}`)
		}
		const currentTarget = path.resolve(path.dirname(output), readlinkSync(output))
		if (realpathSync.native(currentTarget) !== realpathSync.native(target)) {
			throw new Error(`Managed build link has the wrong target: ${output} -> ${currentTarget}`)
		}
	} catch (error) {
		if (error?.code !== 'ENOENT') throw error
		symlinkSync(target, output, 'dir')
	}
	return output
}

export function materializeManagedBuildOutput(projectRoot, name) {
	const { output, packState, target } = resolveManagedBuildOutput(projectRoot, name)
	ensureManagedBuildOutput(projectRoot, name)
	rmSync(output)
	cpSync(target, output, { recursive: true })
	writeFileSync(packState, `${output}\n`)
}

export function restoreManagedBuildOutput(projectRoot, name) {
	const { output, packState, target } = resolveManagedBuildOutput(projectRoot, name)
	if (!existsSync(packState)) return ensureManagedBuildOutput(projectRoot, name)
	if (readFileSync(packState, 'utf8').trim() !== output) {
		throw new Error(`Managed pack state does not match output: ${packState}`)
	}
	rmSync(output, { force: true, recursive: true })
	symlinkSync(target, output, 'dir')
	rmSync(packState)
	return output
}
