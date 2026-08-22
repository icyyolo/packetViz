import { createHash } from 'node:crypto'
import fc from 'fast-check'
import { describe, expect, it } from 'vitest'
import {
  PCAP_MAX_PACKETS,
  frameAt,
  readPcap,
  relativeMs,
  type PcapCapture,
  type PcapReadResult,
} from '../src/core/pcap/read.ts'
import {
  LINKTYPE_ETHERNET,
  PCAP_EPOCH_SECONDS,
  PCAP_GLOBAL_HEADER_BYTES,
  PCAP_RECORD_HEADER_BYTES,
  PCAP_SNAPLEN,
  pcapByteLength,
  writePcap,
  type PcapPacket,
} from '../src/core/pcap/write.ts'
import { arpExchange, arpRequestFrame, dhcpExchange } from './fixtures.ts'
import { toHex } from './util.ts'

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex')
}

function u32be(bytes: Uint8Array, offset: number): number {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset, false)
}

describe('pcap writer', () => {
  it('writes 24 + n*(16 + frame) bytes', () => {
    const file = writePcap(arpExchange())
    expect(file.length).toBe(PCAP_GLOBAL_HEADER_BYTES + 2 * (PCAP_RECORD_HEADER_BYTES + 60))
    expect(file.length).toBe(176)
    expect(pcapByteLength(arpExchange())).toBe(file.length)
  })

  it('starts with the classic magic and a v2.4 header', () => {
    const file = writePcap(arpExchange())
    expect(toHex(file.subarray(0, PCAP_GLOBAL_HEADER_BYTES))).toBe(
      'a1b2c3d4' + '0002' + '0004' + '00000000' + '00000000' + '0000ffff' + '00000001',
    )
    expect(u32be(file, 0)).toBe(0xa1b2c3d4)
    expect(u32be(file, 16)).toBe(PCAP_SNAPLEN)
    expect(u32be(file, 20)).toBe(LINKTYPE_ETHERNET)
  })

  it('derives timestamps from the fixed epoch, so exports are reproducible', () => {
    const file = writePcap(arpExchange())
    const second = PCAP_GLOBAL_HEADER_BYTES + PCAP_RECORD_HEADER_BYTES + 60

    expect(u32be(file, PCAP_GLOBAL_HEADER_BYTES)).toBe(PCAP_EPOCH_SECONDS)
    expect(u32be(file, PCAP_GLOBAL_HEADER_BYTES + 4)).toBe(0)
    expect(u32be(file, second)).toBe(PCAP_EPOCH_SECONDS)
    expect(u32be(file, second + 4)).toBe(12_000)
  })

  it('records incl_len and orig_len as the true frame length', () => {
    const file = writePcap(arpExchange())
    expect(u32be(file, PCAP_GLOBAL_HEADER_BYTES + 8)).toBe(60)
    expect(u32be(file, PCAP_GLOBAL_HEADER_BYTES + 12)).toBe(60)
  })

  it('is byte-identical across runs', () => {
    expect(sha256(writePcap(arpExchange()))).toBe(sha256(writePcap(arpExchange())))
  })

  it('matches a pinned SHA-256, so a silent format change fails the build', () => {
    expect(sha256(writePcap(arpExchange()))).toBe('e9e25682a488b3236e164099804b3310645bae46edb7b7187c23aa7122854381')
  })

  it('writes an empty file as a bare global header', () => {
    expect(writePcap([]).length).toBe(PCAP_GLOBAL_HEADER_BYTES)
  })
})

/**
 * A pcap written the other way round: little-endian, and by this test rather
 * than by `write.ts`, so the reader is checked against a file our writer could
 * not have produced. `editcap` produces exactly this shape on x86, and
 * `tests/import.test.ts` runs the real thing.
 */
function writeLittleEndianPcap(
  packets: readonly PcapPacket[],
  magic = 0xd4c3b2a1,
  linkType = LINKTYPE_ETHERNET,
): Uint8Array {
  const total = packets.reduce((sum, p) => sum + 16 + p.frame.length, 24)
  const bytes = new Uint8Array(total)
  const view = new DataView(bytes.buffer)
  view.setUint32(0, magic, false) // the magic itself is a byte pattern, not a number
  view.setUint16(4, 2, true)
  view.setUint16(6, 4, true)
  view.setUint32(16, PCAP_SNAPLEN, true)
  view.setUint32(20, linkType, true)

  let offset = 24
  for (const packet of packets) {
    const tMs = Math.round(packet.tMs)
    view.setUint32(offset, PCAP_EPOCH_SECONDS + Math.floor(tMs / 1000), true)
    view.setUint32(offset + 4, (tMs % 1000) * 1000, true)
    view.setUint32(offset + 8, packet.frame.length, true)
    view.setUint32(offset + 12, packet.frame.length, true)
    bytes.set(packet.frame, offset + 16)
    offset += 16 + packet.frame.length
  }
  return bytes
}

function expectOk(result: PcapReadResult): PcapCapture {
  if (!result.ok) throw new Error(`expected a readable capture, got: ${result.message}`)
  return result.capture
}

describe('pcap reader', () => {
  it('round-trips what the writer produced, frame for frame', () => {
    const packets = dhcpExchange()
    const capture = expectOk(readPcap(writePcap(packets)))

    expect(capture.totalRecords).toBe(4)
    expect(capture.records).toHaveLength(4)
    expect(capture.byteOrder).toBe('big-endian')
    expect(capture.linkType).toBe(LINKTYPE_ETHERNET)
    expect(capture.warnings).toEqual([])

    capture.records.forEach((record, index) => {
      expect(toHex(frameAt(capture, record))).toBe(toHex(packets[index]!.frame))
      expect(relativeMs(capture, record)).toBeCloseTo(packets[index]!.tMs, 6)
    })
  })

  it('reads a little-endian file, which is what every x86 capture tool writes', () => {
    const packets = arpExchange()
    const capture = expectOk(readPcap(writeLittleEndianPcap(packets)))

    expect(capture.byteOrder).toBe('little-endian')
    expect(capture.records).toHaveLength(2)
    expect(toHex(frameAt(capture, capture.records[1]!))).toBe(toHex(packets[1]!.frame))
    expect(relativeMs(capture, capture.records[1]!)).toBeCloseTo(12, 6)
  })

  it('reads the nanosecond-resolution magic and normalises the sub-second field', () => {
    // 0x4d3cb2a1: little-endian, nanoseconds. The writer above stores
    // microseconds, so 12 ms is written as 12_000 and must read back as 12 us.
    const capture = expectOk(readPcap(writeLittleEndianPcap(arpExchange(), 0x4d3cb2a1)))
    expect(capture.timeResolution).toBe('nanosecond')
    expect(capture.records[1]!.tsUsec).toBe(12)
  })

  it('names pcapng rather than calling it corrupt — Wireshark saves it by default', () => {
    const bytes = new Uint8Array(64)
    new DataView(bytes.buffer).setUint32(0, 0x0a0d0d0a, false)
    const result = readPcap(bytes)

    expect(result.ok).toBe(false)
    expect(result.ok ? '' : result.message).toMatch(/pcapng/)
    expect(result.ok ? '' : result.message).toMatch(/editcap -F pcap/)
  })

  it('rejects a link-layer type it cannot decode, and says which one', () => {
    const result = readPcap(writeLittleEndianPcap(arpExchange(), 0xd4c3b2a1, 101))

    expect(result.ok).toBe(false)
    expect(result.ok ? '' : result.message).toMatch(/101 \(raw IP\)/)
    expect(result.ok ? '' : result.message).toMatch(/only decodes Ethernet/)
  })

  it('refuses a record that runs past the end of the file instead of allocating it', () => {
    const file = writePcap(arpExchange())
    // Claim 60,000 bytes for the second frame; the file holds 60.
    const view = new DataView(file.buffer, file.byteOffset, file.byteLength)
    view.setUint32(24 + 16 + 60 + 8, 60_000, false)

    const capture = expectOk(readPcap(file))
    expect(capture.records).toHaveLength(1)
    expect(capture.totalRecords).toBe(1)
    expect(capture.warnings[0]).toMatch(/ends mid-packet/)
  })

  it('caps the record list and reports what it left out', () => {
    const frame = arpRequestFrame()
    const many: PcapPacket[] = Array.from({ length: 20_000 }, (_, index) => ({
      frame,
      tMs: index,
    }))
    const file = writePcap(many)

    const started = performance.now()
    const capture = expectOk(readPcap(file))
    const elapsedMs = performance.now() - started

    expect(capture.records).toHaveLength(PCAP_MAX_PACKETS)
    expect(capture.totalRecords).toBe(20_000)
    // The walk touches 16 bytes per record and decodes nothing.
    expect(elapsedMs).toBeLessThan(1000)
  })

  it('hands out views, not copies, so selecting a packet allocates nothing', () => {
    const capture = expectOk(readPcap(writePcap(arpExchange())))
    const frame = frameAt(capture, capture.records[0]!)

    expect(frame.buffer).toBe(capture.bytes.buffer)
    expect(frame.byteOffset).toBe(capture.records[0]!.frameOffset)
  })

  it('never throws, whatever the bytes are', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 400 }), (bytes) => {
        const result = readPcap(bytes)
        // Either a capture or a message: never an exception, never a blank.
        if (!result.ok) expect(result.message.length).toBeGreaterThan(0)
        else expect(result.capture.records.length).toBeGreaterThan(0)
      }),
      { numRuns: 2000 },
    )
  })

  it('explains a file that is too short to be a pcap at all', () => {
    const result = readPcap(new Uint8Array(8))
    expect(result.ok).toBe(false)
    expect(result.ok ? '' : result.message).toMatch(/24-byte global header/)
  })
})
