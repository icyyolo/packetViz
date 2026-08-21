import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  LINKTYPE_ETHERNET,
  PCAP_EPOCH_SECONDS,
  PCAP_GLOBAL_HEADER_BYTES,
  PCAP_RECORD_HEADER_BYTES,
  PCAP_SNAPLEN,
  pcapByteLength,
  writePcap,
} from '../src/core/pcap/write.ts'
import { arpExchange } from './fixtures.ts'
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
