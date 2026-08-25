import path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
	materializeManagedBuildOutput,
	restoreManagedBuildOutput
} from './managedBuildOutput.ts'

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const action = process.argv[2]

if (action === 'materialize') materializeManagedBuildOutput(packageRoot, 'dist')
else if (action === 'restore') restoreManagedBuildOutput(packageRoot, 'dist')
else throw new Error('Expected pack dist action: materialize or restore')
