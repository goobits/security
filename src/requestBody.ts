/**
 * Bounded request-body readers.
 *
 * @module @goobits/security/request-body
 */

import { reportDetachedError } from './_reportDetachedError.js'

const DEFAULT_MAX_BODY_BYTES = 1_048_576

/** Error raised when a bounded request-body reader exceeds its configured limit. */
export class BodyTooLargeError extends Error {
	readonly maxBytes: number

	constructor(maxBytes: number) {
		super(`Request body exceeds ${maxBytes} bytes`)
		this.name = 'BodyTooLargeError'
		this.maxBytes = maxBytes
	}
}

/** Shared byte-limit options for bounded request-body readers. */
export interface ReadBodyOptions {
	/** Maximum bytes to read before failing. Default: 1 MiB. */
	maxBytes?: number
}

function resolveMaxBytes(options: ReadBodyOptions): number {
	const maxBytes = options.maxBytes ?? DEFAULT_MAX_BODY_BYTES
	if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
		throw new TypeError('maxBytes must be a positive safe integer')
	}
	return maxBytes
}

function concatenateChunks(
	chunks: readonly Uint8Array[],
	byteLength: number
): Uint8Array<ArrayBuffer> {
	const bytes = new Uint8Array(new ArrayBuffer(byteLength))
	let offset = 0
	for (const chunk of chunks) {
		bytes.set(chunk, offset)
		offset += chunk.byteLength
	}
	return bytes
}

/**
 * Reads a generic async byte/string stream into one bounded byte array.
 *
 * Node `IncomingMessage` streams yield `Buffer` values, which satisfy the
 * `Uint8Array` input without making this cross-runtime package depend on Node.
 */
export async function readAsyncIterableBytes(
	source: AsyncIterable<Uint8Array | string> | Iterable<Uint8Array | string>,
	options: ReadBodyOptions = {}
): Promise<Uint8Array> {
	const maxBytes = resolveMaxBytes(options)
	const encoder = new TextEncoder()
	const chunks: Uint8Array[] = []
	let bytesRead = 0

	for await (const chunk of source) {
		const bytes = typeof chunk === 'string' ? encoder.encode(chunk) : chunk
		bytesRead += bytes.byteLength
		if (bytesRead > maxBytes) throw new BodyTooLargeError(maxBytes)
		chunks.push(bytes)
	}

	return concatenateChunks(chunks, bytesRead)
}

/** Reads a Fetch request body into one bounded `ArrayBuffer`. */
export async function readRequestBodyBytes(
	request: Request,
	options: ReadBodyOptions = {}
): Promise<ArrayBuffer | undefined> {
	const maxBytes = resolveMaxBytes(options)
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
				// A cloned Fetch body is a tee'd stream. Awaiting cancellation can
				// deadlock until the untouched original branch is consumed, so start
				// cancellation without delaying the bounded-body rejection.
				void reader.cancel().catch(error => {
					reportDetachedError('Bounded request-body cancellation failed.', error)
				})
				throw new BodyTooLargeError(maxBytes)
			}
			chunks.push(value)
		}
	} finally {
		reader.releaseLock()
	}

	return concatenateChunks(chunks, bytesRead).buffer
}

/** Parses a bounded Fetch request body as JSON. */
export async function readJsonBody(
	request: Request,
	options: ReadBodyOptions = {}
): Promise<unknown> {
	const bytes = await readRequestBodyBytes(request, options)
	if (bytes === undefined) return undefined
	return JSON.parse(new TextDecoder().decode(bytes))
}

/** Parses a bounded Fetch request body with the runtime's FormData implementation. */
export async function readFormDataBody(
	request: Request,
	options: ReadBodyOptions = {}
): Promise<FormData> {
	const bytes = await readRequestBodyBytes(request, options)
	const boundedRequest = new Request(request.url, {
		method: request.method,
		headers: request.headers,
		body: bytes ?? new ArrayBuffer(0)
	})
	return boundedRequest.formData()
}
