import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { access, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('../', import.meta.url))
const packageJson = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'))
const tempDir = await mkdtemp(join(tmpdir(), 'goobits-security-package-'))

assert.deepEqual(
	Object.keys(packageJson.publishConfig.exports),
	Object.keys(packageJson.exports),
	'workspace and published export subpaths must stay aligned'
)

function run(command, args, cwd = root) {
	return new Promise((resolve, reject) => {
		const child = spawn(command, args, {
			cwd,
			env: { ...process.env, npm_config_update_notifier: 'false' },
			stdio: ['ignore', 'pipe', 'pipe']
		})
		let stdout = ''
		let stderr = ''
		child.stdout.setEncoding('utf8')
		child.stderr.setEncoding('utf8')
		child.stdout.on('data', (chunk) => {
			stdout += chunk
		})
		child.stderr.on('data', (chunk) => {
			stderr += chunk
		})
		child.on('error', reject)
		child.on('exit', (code) => {
			if (code === 0) {
				resolve(stdout)
			} else {
				reject(new Error(`${command} ${args.join(' ')} exited with ${code}\n${stdout}${stderr}`))
			}
		})
	})
}

async function listFiles(directory, prefix = '') {
	const entries = await readdir(directory, { withFileTypes: true })
	const files = []
	for (const entry of entries) {
		const path = join(directory, entry.name)
		const relativePath = prefix ? `${prefix}/${entry.name}` : entry.name
		if (entry.isDirectory()) {
			files.push(...(await listFiles(path, relativePath)))
		} else {
			files.push(relativePath)
		}
	}
	return files
}

function packageSpecifier(subpath) {
	return subpath === '.' ? packageJson.name : `${packageJson.name}${subpath.slice(1)}`
}

try {
	await run('pnpm', ['pack', '--pack-destination', tempDir])
	const tarballs = (await readdir(tempDir)).filter((file) => file.endsWith('.tgz'))
	assert.equal(tarballs.length, 1, 'package verification must produce exactly one tarball')

	const consumerDir = join(tempDir, 'consumer')
	const tarballPath = join(tempDir, tarballs[0])
	const tarballReference = relative(consumerDir, tarballPath).split(sep).join('/')
	await mkdir(consumerDir)
	await writeFile(
		join(consumerDir, 'package.json'),
		JSON.stringify(
			{
				name: 'goobits-security-package-smoke',
				private: true,
				type: 'module',
				dependencies: { [packageJson.name]: `file:${tarballReference}` }
			},
			null,
			2
		)
	)
	await run(
		'pnpm',
		['install', '--prefer-offline', '--ignore-scripts', '--no-frozen-lockfile'],
		consumerDir
	)

	const installedRoot = join(consumerDir, 'node_modules', '@goobits', 'security')
	const installedManifest = JSON.parse(await readFile(join(installedRoot, 'package.json'), 'utf8'))
	assert.equal(installedManifest.main, './dist/index.js')
	assert.equal(installedManifest.types, './dist/index.d.ts')
	assert.deepEqual(installedManifest.exports, packageJson.publishConfig.exports)

	for (const [subpath, conditions] of Object.entries(installedManifest.exports)) {
		assert.deepEqual(Object.keys(conditions), ['types', 'default'], `${subpath} export conditions`)
		for (const [condition, target] of Object.entries(conditions)) {
			assert.match(target, /^\.\/dist\//, `${subpath} ${condition} must resolve from dist`)
			await access(join(installedRoot, target))
			if (condition === 'types') assert.match(target, /\.d\.ts$/)
			if (condition === 'default') assert.match(target, /\.js$/)
		}
	}

	const packedFiles = await listFiles(installedRoot)
	for (const required of ['dist/index.js', 'dist/index.d.ts', 'README.md', 'LICENSE']) {
		assert(packedFiles.includes(required), `packed artifact is missing ${required}`)
	}
	const forbiddenPrefixes = [
		'.github/',
		'.llm/',
		'__tests__/',
		'done/',
		'pending/',
		'scripts/',
		'src/'
	]
	assert(
		!packedFiles.some((file) => forbiddenPrefixes.some((prefix) => file.startsWith(prefix))),
		'packed artifact contains repository-only files'
	)
	assert(!packedFiles.some((file) => file.endsWith('.ts') && !file.endsWith('.d.ts')))

	const smokePath = join(consumerDir, 'smoke.mjs')
	await writeFile(
		smokePath,
		`for (const specifier of ${JSON.stringify(Object.keys(installedManifest.exports).map(packageSpecifier))}) {\n\tawait import(specifier)\n}\n`
	)
	await run(process.execPath, [smokePath], consumerDir)

	console.log(`package smoke passed (${Object.keys(installedManifest.exports).length} entrypoints)`)
} finally {
	await rm(tempDir, { recursive: true, force: true })
}
