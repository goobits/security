/**
 * Bounded request-body readers.
 *
 * @internal
 */

const DEFAULT_MAX_BODY_BYTES = 1_048_576

export class BodyTooLargeError extends Error {
	constructor(readonly maxBytes: number) {
		super(`Request body exceeds ${ maxBytes } bytes`)
		this.name = 'BodyTooLargeError'
	}
}

interface ReadBodyOptions {
	/** Maximum bytes to read before failing. Default: 1 MiB. */
	maxBytes?: number
}

export async function readRequestBodyBytes(
	request: Request,
	options: ReadBodyOptions = {}
): Promise<ArrayBuffer | undefined> {
	const maxBytes = options.maxBytes ?? DEFAULT_MAX_BODY_BYTES
	const contentLength = request.headers.get('content-length')
	if (contentLength) {
		const parsed = Number(contentLength)
		if (Number.isFinite(parsed) && parsed > maxBytes) {
			throw new BodyTooLargeError(maxBytes)
		}
	}

	if (!request.body) return undefined

	const reader = request.body.getReader()
	let bytesRead = 0
	const chunks: Uint8Array[] = []

	try {
		while (true) {
			const { done, value } = await reader.read()
			if (done) break
			bytesRead += value.byteLength
			if (bytesRead > maxBytes) {
				await reader.cancel()
				throw new BodyTooLargeError(maxBytes)
			}
			chunks.push(value)
		}
	} finally {
		reader.releaseLock()
	}

	const bytes = new Uint8Array(bytesRead)
	let offset = 0
	for (const chunk of chunks) {
		bytes.set(chunk, offset)
		offset += chunk.byteLength
	}
	return bytes.buffer
}

export async function readJsonBody(
	request: Request,
	options: ReadBodyOptions = {}
): Promise<unknown> {
	const bytes = await readRequestBodyBytes(request, options)
	if (bytes === undefined) return undefined
	return JSON.parse(new TextDecoder().decode(bytes))
}
