import { importAesGcmKey } from './_aesGcm.js'
import { randomBytes, textToBytes } from './encoding.js'

const MAGIC = Uint8Array.from([0x47, 0x46, 0x41, 0x45]) // GFAE
const VERSION = 1
const ALGORITHM_AES_GCM = 1
const DATA_FRAME = 1
const FINAL_FRAME = 2
const STREAM_ID_SIZE = 16
const FRAME_IV_SIZE = 12
const HEADER_SIZE = 10 + STREAM_ID_SIZE
const FRAME_HEADER_SIZE = 9 + FRAME_IV_SIZE
const GCM_TAG_SIZE = 16
const DEFAULT_CHUNK_SIZE = 64 * 1024
const MAX_CHUNK_SIZE = 16 * 1024 * 1024
const MAX_ASSOCIATED_DATA_SIZE = 64 * 1024
const MAX_FRAME_INDEX = 0xffff_ffff
const DOMAIN = textToBytes('@goobits/security/framed-aead/v1')

type BinaryValue = Uint8Array | string

export type FramedAeadEncryptOptions = {
	key: BinaryValue
	associatedData?: BinaryValue
	chunkSize?: number
}

export type FramedAeadDecryptOptions = {
	key: BinaryValue
	associatedData?: BinaryValue
	maxChunkSize?: number
}

type ParsedHeader = {
	bytes: Uint8Array
	chunkSize: number
}

type ParsedFrameHeader = {
	bytes: Uint8Array
	ciphertextLength: number
	index: number
	iv: Uint8Array
	type: number
}

class ByteQueue {
	private chunks: Uint8Array[] = []
	private head = 0
	private offset = 0
	private total = 0

	get length(): number {
		return this.total
	}

	push(chunk: Uint8Array): void {
		if (chunk.byteLength === 0) return
		this.chunks.push(chunk)
		this.total += chunk.byteLength
	}

	read(length: number): Uint8Array {
		if (!Number.isSafeInteger(length) || length < 0 || length > this.total) {
			throw invalidStream()
		}
		const output = new Uint8Array(length)
		let written = 0
		while (written < length) {
			const chunk = this.chunks[this.head]
			if (!chunk) throw invalidStream()
			const available = chunk.byteLength - this.offset
			const take = Math.min(available, length - written)
			output.set(chunk.subarray(this.offset, this.offset + take), written)
			written += take
			this.offset += take
			this.total -= take
			if (this.offset === chunk.byteLength) {
				this.head += 1
				this.offset = 0
				if (this.head >= 1024 && this.head * 2 >= this.chunks.length) {
					this.chunks = this.chunks.slice(this.head)
					this.head = 0
				}
			}
		}
		return output
	}
}

function invalidStream(): Error {
	return new Error('@goobits/security/crypto: invalid framed AEAD stream')
}

function normalizeBinary(value: BinaryValue | undefined): Uint8Array {
	if (value === undefined) return new Uint8Array()
	return typeof value === 'string' ? textToBytes(value) : value
}

function assertChunkSize(value: number, maximum = MAX_CHUNK_SIZE): number {
	if (
		!Number.isSafeInteger(value) ||
		value < 1 ||
		!Number.isSafeInteger(maximum) ||
		maximum < 1 ||
		maximum > MAX_CHUNK_SIZE ||
		value > maximum
	) {
		throw new Error('@goobits/security/crypto: invalid framed AEAD chunk size')
	}
	return value
}

function normalizeAssociatedData(value: BinaryValue | undefined): Uint8Array {
	const bytes = normalizeBinary(value)
	if (bytes.byteLength > MAX_ASSOCIATED_DATA_SIZE) {
		throw new Error('@goobits/security/crypto: framed AEAD associated data is too large')
	}
	return bytes.slice()
}

function writeUint32(target: Uint8Array, offset: number, value: number): void {
	new DataView(target.buffer, target.byteOffset, target.byteLength).setUint32(offset, value)
}

function readUint32(source: Uint8Array, offset: number): number {
	return new DataView(source.buffer, source.byteOffset, source.byteLength).getUint32(offset)
}

function buildHeader(chunkSize: number): ParsedHeader {
	const bytes = new Uint8Array(HEADER_SIZE)
	bytes.set(MAGIC)
	bytes[4] = VERSION
	bytes[5] = ALGORITHM_AES_GCM
	writeUint32(bytes, 6, chunkSize)
	bytes.set(randomBytes(STREAM_ID_SIZE), 10)
	return { bytes, chunkSize }
}

function parseHeader(bytes: Uint8Array, maxChunkSize: number): ParsedHeader {
	if (
		bytes.byteLength !== HEADER_SIZE ||
		!MAGIC.every((value, index) => bytes[index] === value) ||
		bytes[4] !== VERSION ||
		bytes[5] !== ALGORITHM_AES_GCM
	) {
		throw invalidStream()
	}
	let chunkSize: number
	try {
		chunkSize = assertChunkSize(readUint32(bytes, 6), maxChunkSize)
	} catch {
		throw invalidStream()
	}
	return { bytes, chunkSize }
}

function buildFrameHeader(
	type: number,
	index: number,
	ciphertextLength: number,
	iv: Uint8Array
): Uint8Array {
	const bytes = new Uint8Array(FRAME_HEADER_SIZE)
	bytes[0] = type
	writeUint32(bytes, 1, index)
	writeUint32(bytes, 5, ciphertextLength)
	bytes.set(iv, 9)
	return bytes
}

function parseFrameHeader(bytes: Uint8Array, header: ParsedHeader): ParsedFrameHeader {
	if (bytes.byteLength !== FRAME_HEADER_SIZE) throw invalidStream()
	const type = bytes[0] ?? 0
	const index = readUint32(bytes, 1)
	const ciphertextLength = readUint32(bytes, 5)
	const iv = bytes.slice(9, 9 + FRAME_IV_SIZE)
	const plaintextLength = ciphertextLength - GCM_TAG_SIZE
	if (
		(type !== DATA_FRAME && type !== FINAL_FRAME) ||
		ciphertextLength < GCM_TAG_SIZE ||
		(type === DATA_FRAME && (plaintextLength < 1 || plaintextLength > header.chunkSize)) ||
		(type === FINAL_FRAME && plaintextLength !== 0)
	) {
		throw invalidStream()
	}
	return { bytes, ciphertextLength, index, iv, type }
}

function buildStreamAssociatedData(
	streamHeader: Uint8Array,
	associatedData: Uint8Array
): Uint8Array {
	const output = new Uint8Array(
		4 + DOMAIN.byteLength + 4 + associatedData.byteLength + streamHeader.byteLength
	)
	let offset = 0
	writeUint32(output, offset, DOMAIN.byteLength)
	offset += 4
	output.set(DOMAIN, offset)
	offset += DOMAIN.byteLength
	writeUint32(output, offset, associatedData.byteLength)
	offset += 4
	output.set(associatedData, offset)
	offset += associatedData.byteLength
	output.set(streamHeader, offset)
	return output
}

function buildFrameAssociatedData(prefix: Uint8Array, frameHeader: Uint8Array): Uint8Array {
	const output = new Uint8Array(prefix.byteLength + frameHeader.byteLength)
	output.set(prefix)
	output.set(frameHeader, prefix.byteLength)
	return output
}

function assertInputChunk(chunk: Uint8Array): void {
	if (!(chunk instanceof Uint8Array)) {
		throw new TypeError('@goobits/security/crypto: framed AEAD streams require Uint8Array chunks')
	}
}

async function encryptFrame(options: {
	associatedDataPrefix: Uint8Array
	controller: TransformStreamDefaultController<Uint8Array>
	index: number
	key: CryptoKey
	plaintext: Uint8Array
	type: number
}): Promise<void> {
	const iv = randomBytes(FRAME_IV_SIZE)
	const frameHeader = buildFrameHeader(
		options.type,
		options.index,
		options.plaintext.byteLength + GCM_TAG_SIZE,
		iv
	)
	const ciphertext = await crypto.subtle.encrypt(
		{
			name: 'AES-GCM',
			iv: iv as never,
			additionalData: buildFrameAssociatedData(options.associatedDataPrefix, frameHeader) as never
		},
		options.key,
		options.plaintext as never
	)
	options.controller.enqueue(frameHeader)
	options.controller.enqueue(new Uint8Array(ciphertext))
}

/**
 * Creates a bounded-memory AES-GCM encrypting stream with authenticated,
 * ordered frames and a required terminal frame.
 */
export function createFramedAeadEncryptStream(
	options: FramedAeadEncryptOptions
): TransformStream<Uint8Array, Uint8Array> {
	const chunkSize = assertChunkSize(options.chunkSize ?? DEFAULT_CHUNK_SIZE)
	const associatedData = normalizeAssociatedData(options.associatedData)
	const header = buildHeader(chunkSize)
	const associatedDataPrefix = buildStreamAssociatedData(header.bytes, associatedData)
	const key = importAesGcmKey(options.key, 'encrypt')
	let pending = new Uint8Array()
	let frameIndex = 0

	const emitData = async (
		plaintext: Uint8Array,
		controller: TransformStreamDefaultController<Uint8Array>
	) => {
		if (frameIndex >= MAX_FRAME_INDEX) throw invalidStream()
		await encryptFrame({
			associatedDataPrefix,
			controller,
			index: frameIndex,
			key: await key,
			plaintext,
			type: DATA_FRAME
		})
		frameIndex += 1
	}

	return new TransformStream({
		start(controller) {
			controller.enqueue(header.bytes.slice())
		},
		async transform(chunk, controller) {
			assertInputChunk(chunk)
			let offset = 0
			if (pending.byteLength > 0) {
				const needed = chunkSize - pending.byteLength
				const take = Math.min(needed, chunk.byteLength)
				const combined = new Uint8Array(pending.byteLength + take)
				combined.set(pending)
				combined.set(chunk.subarray(0, take), pending.byteLength)
				pending = combined
				offset = take
				if (pending.byteLength === chunkSize) {
					await emitData(pending, controller)
					pending = new Uint8Array()
				}
			}
			while (chunk.byteLength - offset >= chunkSize) {
				await emitData(chunk.subarray(offset, offset + chunkSize), controller)
				offset += chunkSize
			}
			if (offset < chunk.byteLength) {
				pending = chunk.slice(offset)
			}
		},
		async flush(controller) {
			if (pending.byteLength > 0) {
				await emitData(pending, controller)
				pending = new Uint8Array()
			}
			await encryptFrame({
				associatedDataPrefix,
				controller,
				index: frameIndex,
				key: await key,
				plaintext: new Uint8Array(),
				type: FINAL_FRAME
			})
		}
	})
}

/**
 * Creates a bounded-memory decrypting stream for the versioned framed-AEAD
 * format. Missing, duplicate, reordered, or trailing frames fail closed.
 */
export function createFramedAeadDecryptStream(
	options: FramedAeadDecryptOptions
): TransformStream<Uint8Array, Uint8Array> {
	const maxChunkSize = assertChunkSize(options.maxChunkSize ?? MAX_CHUNK_SIZE)
	const associatedData = normalizeAssociatedData(options.associatedData)
	const key = importAesGcmKey(options.key, 'decrypt')
	const queue = new ByteQueue()
	let header: ParsedHeader | null = null
	let frameHeader: ParsedFrameHeader | null = null
	let expectedFrameIndex = 0
	let finished = false
	let associatedDataPrefix: Uint8Array | null = null

	const drain = async (controller: TransformStreamDefaultController<Uint8Array>) => {
		while (true) {
			if (finished) {
				if (queue.length > 0) throw invalidStream()
				return
			}
			if (!header) {
				if (queue.length < HEADER_SIZE) return
				header = parseHeader(queue.read(HEADER_SIZE), maxChunkSize)
				associatedDataPrefix = buildStreamAssociatedData(header.bytes, associatedData)
			}
			if (!frameHeader) {
				if (queue.length < FRAME_HEADER_SIZE) return
				frameHeader = parseFrameHeader(queue.read(FRAME_HEADER_SIZE), header)
				if (frameHeader.index !== expectedFrameIndex) throw invalidStream()
			}
			if (queue.length < frameHeader.ciphertextLength) return
			const ciphertext = queue.read(frameHeader.ciphertextLength)
			const frameAssociatedDataPrefix = associatedDataPrefix
			if (!frameAssociatedDataPrefix) throw invalidStream()
			let plaintext: ArrayBuffer
			try {
				plaintext = await crypto.subtle.decrypt(
					{
						name: 'AES-GCM',
						iv: frameHeader.iv as never,
						additionalData: buildFrameAssociatedData(
							frameAssociatedDataPrefix,
							frameHeader.bytes
						) as never
					},
					await key,
					ciphertext as never
				)
			} catch {
				throw invalidStream()
			}
			const frameType = frameHeader.type
			const opened = new Uint8Array(plaintext)
			frameHeader = null
			expectedFrameIndex += 1
			if (frameType === FINAL_FRAME) {
				finished = true
				if (opened.byteLength !== 0 || queue.length > 0) throw invalidStream()
				return
			}
			if (expectedFrameIndex > MAX_FRAME_INDEX) throw invalidStream()
			controller.enqueue(opened)
		}
	}

	return new TransformStream({
		async transform(chunk, controller) {
			assertInputChunk(chunk)
			queue.push(chunk)
			await drain(controller)
		},
		async flush(controller) {
			await drain(controller)
			if (!finished || queue.length > 0 || frameHeader !== null) throw invalidStream()
		}
	})
}
