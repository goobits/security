import { describe, expect, it } from 'vitest'

import {
	createFramedAeadDecryptStream,
	createFramedAeadEncryptStream,
	randomBytes,
	textToBytes
} from '../src/crypto/index.js'

function readable(chunks: Uint8Array[]): ReadableStream<Uint8Array> {
	return new ReadableStream({
		start(controller) {
			for (const chunk of chunks) controller.enqueue(chunk)
			controller.close()
		}
	})
}

async function collect(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
	const chunks: Uint8Array[] = []
	let length = 0
	const reader = stream.getReader()
	while (true) {
		const result = await reader.read()
		if (result.done) break
		chunks.push(result.value)
		length += result.value.byteLength
	}
	const output = new Uint8Array(length)
	let offset = 0
	for (const chunk of chunks) {
		output.set(chunk, offset)
		offset += chunk.byteLength
	}
	return output
}

function fragment(bytes: Uint8Array, sizes: number[]): Uint8Array[] {
	const chunks: Uint8Array[] = []
	let offset = 0
	let sizeIndex = 0
	while (offset < bytes.byteLength) {
		const size = sizes[sizeIndex % sizes.length] ?? 1
		chunks.push(bytes.slice(offset, Math.min(offset + size, bytes.byteLength)))
		offset += size
		sizeIndex += 1
	}
	return chunks
}

function readUint32(bytes: Uint8Array, offset: number): number {
	return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset)
}

async function encrypt(
	plaintext: Uint8Array,
	options: { associatedData?: string; chunkSize?: number; key: Uint8Array }
): Promise<Uint8Array> {
	return collect(
		readable(fragment(plaintext, [1, 9, 3, 64])).pipeThrough(createFramedAeadEncryptStream(options))
	)
}

async function decrypt(
	ciphertext: Uint8Array,
	options: { associatedData?: string; key: Uint8Array }
): Promise<Uint8Array> {
	return collect(
		readable(fragment(ciphertext, [2, 1, 17, 5])).pipeThrough(
			createFramedAeadDecryptStream(options)
		)
	)
}

describe('framed AEAD streams', () => {
	it('round-trips empty, partial, and multi-frame streams across arbitrary boundaries', async () => {
		const key = randomBytes(32)
		for (const plaintext of [new Uint8Array(), textToBytes('short payload'), randomBytes(257)]) {
			const encrypted = await encrypt(plaintext, {
				key,
				associatedData: 'artifact:part-1',
				chunkSize: 32
			})
			await expect(decrypt(encrypted, { key, associatedData: 'artifact:part-1' })).resolves.toEqual(
				plaintext
			)
		}
	})

	it('emits authenticated frames before the plaintext source closes', async () => {
		const key = randomBytes(32)
		let source: ReadableStreamDefaultController<Uint8Array> | undefined
		const encrypted = new ReadableStream<Uint8Array>({
			start(controller) {
				source = controller
			}
		}).pipeThrough(createFramedAeadEncryptStream({ key, chunkSize: 4 }))
		const reader = encrypted.getReader()

		await expect(reader.read()).resolves.toMatchObject({ done: false })
		source?.enqueue(textToBytes('four'))
		await expect(reader.read()).resolves.toMatchObject({ done: false })
		await expect(reader.read()).resolves.toMatchObject({ done: false })
		await reader.cancel()
	})

	it('rejects wrong keys and associated data without exposing plaintext', async () => {
		const key = randomBytes(32)
		const encrypted = await encrypt(textToBytes('secret'), {
			key,
			associatedData: 'artifact:part-1'
		})

		await expect(decrypt(encrypted, { key: randomBytes(32) })).rejects.toThrow(
			/invalid framed AEAD stream/
		)
		await expect(decrypt(encrypted, { key, associatedData: 'artifact:part-2' })).rejects.toThrow(
			/invalid framed AEAD stream/
		)
	})

	it('rejects tampering, truncation, trailing bytes, and reordered frames', async () => {
		const key = randomBytes(32)
		const encrypted = await encrypt(randomBytes(96), { key, chunkSize: 32 })
		const tampered = encrypted.slice()
		tampered[40] = (tampered[40] ?? 0) ^ 1
		await expect(decrypt(tampered, { key })).rejects.toThrow(/invalid framed AEAD stream/)

		await expect(decrypt(encrypted.slice(0, -1), { key })).rejects.toThrow(
			/invalid framed AEAD stream/
		)

		const trailing = new Uint8Array(encrypted.byteLength + 1)
		trailing.set(encrypted)
		trailing[trailing.byteLength - 1] = 1
		await expect(decrypt(trailing, { key })).rejects.toThrow(/invalid framed AEAD stream/)

		const reordered = encrypted.slice()
		reordered[27] = 1
		await expect(decrypt(reordered, { key })).rejects.toThrow(/invalid framed AEAD stream/)
	})

	it('rejects a valid frame spliced from another encrypted stream', async () => {
		const key = randomBytes(32)
		const first = await encrypt(randomBytes(32), { key, chunkSize: 32 })
		const second = await encrypt(randomBytes(32), { key, chunkSize: 32 })
		const headerSize = 26
		const frameHeaderSize = 21
		const firstFrameSize = frameHeaderSize + readUint32(first, headerSize + 5)
		const spliced = first.slice()
		spliced.set(second.subarray(headerSize, headerSize + firstFrameSize), headerSize)

		await expect(decrypt(spliced, { key })).rejects.toThrow(/invalid framed AEAD stream/)
	})

	it('rejects malformed headers and unsafe stream bounds', async () => {
		const key = randomBytes(32)
		expect(() => createFramedAeadEncryptStream({ key, chunkSize: 0 })).toThrow(
			/invalid framed AEAD chunk size/
		)
		expect(() =>
			createFramedAeadEncryptStream({
				key,
				associatedData: new Uint8Array(64 * 1024 + 1)
			})
		).toThrow(/associated data is too large/)

		const encrypted = await encrypt(textToBytes('payload'), { key })
		const unsupported = encrypted.slice()
		unsupported[4] = 99
		await expect(decrypt(unsupported, { key })).rejects.toThrow(/invalid framed AEAD stream/)
		expect(() => createFramedAeadDecryptStream({ key, maxChunkSize: 32 * 1024 * 1024 })).toThrow(
			/invalid framed AEAD chunk size/
		)
	})

	it('propagates downstream cancellation to the plaintext source', async () => {
		let cancelled = false
		const plaintext = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(randomBytes(128))
			},
			cancel() {
				cancelled = true
			}
		})
		const reader = plaintext
			.pipeThrough(createFramedAeadEncryptStream({ key: randomBytes(32), chunkSize: 32 }))
			.getReader()

		await reader.read()
		await reader.cancel()
		expect(cancelled).toBe(true)
	})
})
