import { defineConfig } from 'vitest/config'
import { resolveTestArtifactDirectory, resolveViteCacheDirectory } from './scripts/testStorage.ts'

export default defineConfig({
	cacheDir: resolveViteCacheDirectory(import.meta.dirname),
	test: {
		...(process.env.CI ? {} : { maxWorkers: 2 }),
		globals: false,
		environment: 'node',
		include: ['__tests__/**/*.test.ts', 'tests/**/*.test.ts'],
		coverage: {
			provider: 'v8',
			reportsDirectory: resolveTestArtifactDirectory(import.meta.dirname, 'coverage'),
			reporter: ['text', 'lcov'],
			include: ['src/**/*.ts'],
			exclude: ['src/_internal/**', '**/*.d.ts', 'src/index.ts'],
			// Enforce a quality floor for the published surface. Tune these up as
			// coverage grows; never silently lower them, each lowering should
			// require a CHANGELOG note explaining why.
			thresholds: {
				lines: 80,
				branches: 75,
				functions: 80,
				statements: 80
			}
		}
	}
})
