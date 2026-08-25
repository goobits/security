import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { ensureManagedBuildOutput } from './managedBuildOutput.ts'

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const distDirectory = ensureManagedBuildOutput(packageRoot, 'dist')

for (const entry of fs.readdirSync(distDirectory)) {
	fs.rmSync(path.join(distDirectory, entry), { force: true, recursive: true })
}
