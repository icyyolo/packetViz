/**
 * Byte-level primitives. Everything in PacketViz ultimately reads or writes a
 * `Uint8Array` through this module.
 *
 * `ByteWriter` is encoder-side: it is allowed to throw, because its inputs come
 * from our own code and a range violation is a bug we want surfaced loudly.
 *
 * `ByteReader` is decoder-side: it is total. Out-of-bounds reads return
 * `undefined` rather than throwing, because its inputs may be hostile
 * (imported .pcap files, hand-edited hex).
 */

const INITIAL_CAPACITY = 64

export class ByteWriter {
  private buf = new Uint8Array(INITIAL_CAPACITY)
  private view = new DataView(this.buf.buffer)
  private len = 0

  get length(): number {
    return this.len
  }

  u8(value: number): this {
    assertRange(value, 0, 0xff, 'u8')
    this.reserve(1)
    this.view.setUint8(this.len, value)
    this.len += 1
    return this
  }

  u16be(value: number): this {
    assertRange(value, 0, 0xffff, 'u16be')
    this.reserve(2)
    this.view.setUint16(this.len, value, false)
    this.len += 2
    return this
  }

  u32be(value: number): this {
    assertRange(value, 0, 0xffffffff, 'u32be')
    this.reserve(4)
    this.view.setUint32(this.len, value, false)
    this.len += 4
    return this
  }

  bytes(source: Uint8Array): this {
    this.reserve(source.length)
    this.buf.set(source, this.len)
    this.len += source.length
    return this
  }

  zeros(count: number): this {
    if (!Number.isInteger(count) || count < 0) {
      throw new RangeError(`zeros(${count}): count must be a non-negative integer`)
    }
    this.reserve(count)
    this.buf.fill(0, this.len, this.len + count)
    this.len += count
    return this
  }

  /** Pad with zeros until at least `size` bytes have been written. */
  padTo(size: number): this {
    if (this.len < size) this.zeros(size - this.len)
    return this
  }

  /** Copy of the bytes written so far. */
  finish(): Uint8Array {
    return this.buf.slice(0, this.len)
  }

  private reserve(extra: number): void {
    const needed = this.len + extra
    if (needed <= this.buf.length) return
    let capacity = this.buf.length
    while (capacity < needed) capacity *= 2
    const next = new Uint8Array(capacity)
    next.set(this.buf.subarray(0, this.len))
    this.buf = next
    this.view = new DataView(next.buffer)
  }
}

function assertRange(value: number, min: number, max: number, what: string): void {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new RangeError(`${what}(${value}): must be an integer in [${min}, ${max}]`)
  }
}

export class ByteReader {
  private readonly frame: Uint8Array
  private readonly view: DataView
  offset: number

  constructor(frame: Uint8Array, offset = 0) {
    this.frame = frame
    this.view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength)
    this.offset = offset
  }

  get remaining(): number {
    return Math.max(0, this.frame.length - this.offset)
  }

  hasBytes(count: number): boolean {
    return this.offset >= 0 && this.remaining >= count
  }

  u8(): number | undefined {
    if (!this.hasBytes(1)) return undefined
    const value = this.view.getUint8(this.offset)
    this.offset += 1
    return value
  }

  u16be(): number | undefined {
    if (!this.hasBytes(2)) return undefined
    const value = this.view.getUint16(this.offset, false)
    this.offset += 2
    return value
  }

  u32be(): number | undefined {
    if (!this.hasBytes(4)) return undefined
    const value = this.view.getUint32(this.offset, false)
    this.offset += 4
    return value
  }

  /** A view (not a copy) of `count` bytes, or `undefined` if they are not all present. */
  bytes(count: number): Uint8Array | undefined {
    if (count < 0 || !this.hasBytes(count)) return undefined
    const value = this.frame.subarray(this.offset, this.offset + count)
    this.offset += count
    return value
  }
}

/**
 * Big-endian read of `bits` bits starting at absolute bit position `bitPos`.
 * Returns `NaN` when the range is out of bounds or wider than 32 bits, so
 * callers must check with `Number.isFinite`.
 */
export function readBits(frame: Uint8Array, bitPos: number, bits: number): number {
  if (bits <= 0 || bits > 32 || bitPos < 0) return Number.NaN
  if ((bitPos + bits + 7) >> 3 > frame.length) return Number.NaN
  let value = 0
  for (let i = 0; i < bits; i++) {
    const p = bitPos + i
    const byte = frame[p >> 3]
    if (byte === undefined) return Number.NaN
    value = value * 2 + ((byte >> (7 - (p & 7))) & 1)
  }
  return value
}
