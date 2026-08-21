import { describe, expect, it } from 'vitest'
import { ByteReader, ByteWriter, readBits } from '../src/core/bytes.ts'
import { fromHex, toHex } from './util.ts'

describe('ByteWriter', () => {
  it('produces the hand-checked byte sequence', () => {
    const out = new ByteWriter()
      .u8(0x01)
      .u16be(0x0806)
      .u32be(0xdeadbeef)
      .bytes(fromHex('aabbcc'))
      .zeros(2)
      .finish()

    expect(toHex(out)).toBe('010806deadbeefaabbcc0000')
    expect(out.length).toBe(12)
  })

  it('grows past its initial capacity without corrupting earlier bytes', () => {
    const writer = new ByteWriter()
    for (let i = 0; i < 300; i++) writer.u8(i & 0xff)
    const out = writer.finish()
    expect(out.length).toBe(300)
    expect(out[0]).toBe(0)
    expect(out[255]).toBe(255)
    expect(out[299]).toBe(299 & 0xff)
  })

  it('pads to a minimum size and leaves longer buffers alone', () => {
    expect(new ByteWriter().u8(0xff).padTo(4).finish()).toEqual(fromHex('ff000000'))
    expect(new ByteWriter().bytes(fromHex('aabbccdd')).padTo(2).finish().length).toBe(4)
  })

  it('throws on out-of-range values, because encoder inputs are our own code', () => {
    expect(() => new ByteWriter().u8(256)).toThrow(RangeError)
    expect(() => new ByteWriter().u8(-1)).toThrow(RangeError)
    expect(() => new ByteWriter().u16be(0x10000)).toThrow(RangeError)
    expect(() => new ByteWriter().u8(1.5)).toThrow(RangeError)
  })
})

describe('ByteReader', () => {
  it('reads big-endian values in sequence', () => {
    const reader = new ByteReader(fromHex('010806deadbeefaabbcc'))
    expect(reader.u8()).toBe(0x01)
    expect(reader.u16be()).toBe(0x0806)
    expect(reader.u32be()).toBe(0xdeadbeef)
    expect(toHex(reader.bytes(3) as Uint8Array)).toBe('aabbcc')
    expect(reader.remaining).toBe(0)
  })

  it('returns undefined instead of throwing past the end', () => {
    const reader = new ByteReader(fromHex('01'))
    expect(reader.u16be()).toBeUndefined()
    expect(reader.offset).toBe(0)
    expect(reader.u8()).toBe(1)
    expect(reader.u8()).toBeUndefined()
    expect(reader.bytes(1)).toBeUndefined()
  })

  it('honours the byteOffset of a subarray view', () => {
    const reader = new ByteReader(fromHex('ffff0806').subarray(2))
    expect(reader.u16be()).toBe(0x0806)
  })
})

describe('readBits', () => {
  it('reads whole-byte and sub-byte ranges big-endian', () => {
    const frame = fromHex('45000806')
    expect(readBits(frame, 0, 4)).toBe(4)
    expect(readBits(frame, 4, 4)).toBe(5)
    expect(readBits(frame, 16, 16)).toBe(0x0806)
    expect(readBits(frame, 0, 32)).toBe(0x45000806)
  })

  it('returns NaN for out-of-bounds or over-wide reads', () => {
    const frame = fromHex('4500')
    expect(readBits(frame, 8, 16)).toBeNaN()
    expect(readBits(frame, 0, 33)).toBeNaN()
    expect(readBits(frame, -1, 8)).toBeNaN()
    expect(readBits(new Uint8Array(0), 0, 8)).toBeNaN()
  })
})
