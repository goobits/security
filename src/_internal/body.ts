/**
 * Bounded request-body readers.
 *
 * @internal
 */

const DEFAULT_MAX_JSON_BODY_BYTES = 1_048_576

export class BodyTooLargeError extends Error {
	constructor(readonly maxBytes: number) {
		super(`Request body exceeds ${ maxBytes } bytes`)
		this.name = 'BodyTooLargeError'
	}
}

export interface ReadJsonBodyOptions {
	/** Maximum bytes to read before failing. Default: 1 MiB. */
	maxBytes?: number
}

export async function readJsonBody(
	request: Request,
	options: ReadJsonBodyOptions = {}
): Promise<unknown> {
	const maxBytes = options.maxBytes ?? DEFAULT_MAX_JSON_BODY_BYTES
	const contentLength = request.headers.get('content-length')
	if (contentLength) {
		const parsed = Number(contentLength)
		if (Number.isFinite(parsed) && parsed > maxBytes) {
			throw new BodyTooLargeError(maxBytes)
		}
	}

	if (!request.body) return undefined

	const reader = request.body.getReader()
	const decoder = new TextDecoder()
	let bytesRead = 0
	let text = ''

	try {
		while (true) {
			const { done, value } = await reader.read()
			if (done) break
			bytesRead += value.byteLength
			if (bytesRead > maxBytes) {
				throw new BodyTooLargeError(maxBytes)
			}
			text += decoder.decode(value, { stream: true })
		}
		text += decoder.decode()
	} finally {
		reader.releaseLock()
	}

	return JSON.parse(text)
}
