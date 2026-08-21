/**
 * Classic libpcap ("pcap", not pcapng) writer.
 *
 * This is the correctness anchor for the whole project: if Wireshark opens what
 * we write and decodes it to the same values our own decoder shows, the encoder
 * is right about the wire format. `tests/tshark-diff.test.ts` runs exactly that
 * comparison on every commit.
 *
 * Everything is written big-endian, so the file literally begins `a1 b2 c3 d4`
 * and a hex dump of the header is readable without byte-swapping. Readers detect
 * endianness from the magic, so this costs nothing.
 *
 * Reference: https://wiki.wireshark.org/Development/LibpcapFileFormat
 */

import { ByteWriter } from '../bytes.ts'

export const PCAP_MAGIC = 0xa1b2c3d4
export const PCAP_VERSION_MAJOR = 2
export const PCAP_VERSION_MINOR = 4
export const PCAP_SNAPLEN = 65535
export const LINKTYPE_ETHERNET = 1

export const PCAP_GLOBAL_HEADER_BYTES = 24
export const PCAP_RECORD_HEADER_BYTES = 16

/**
 * Fixed capture epoch: 2026-01-01T00:00:00Z. Scenario event offsets are added to
 * it, so the same scenario always exports byte-identical bytes and the SHA-256
 * of an export is a meaningful regression check.
 */
export const PCAP_EPOCH_SECONDS = Math.floor(Date.UTC(2026, 0, 1) / 1000)

export type PcapPacket = {
  frame: Uint8Array
  /** Milliseconds after `PCAP_EPOCH_SECONDS`. */
  tMs: number
}

export function writePcap(packets: readonly PcapPacket[]): Uint8Array {
  const writer = new ByteWriter()
    .u32be(PCAP_MAGIC)
    .u16be(PCAP_VERSION_MAJOR)
    .u16be(PCAP_VERSION_MINOR)
    .u32be(0) // thiszone: capture timestamps are already UTC
    .u32be(0) // sigfigs: always 0 in practice
    .u32be(PCAP_SNAPLEN)
    .u32be(LINKTYPE_ETHERNET)

  for (const packet of packets) {
    const tMs = Math.max(0, Math.round(packet.tMs))
    writer
      .u32be(PCAP_EPOCH_SECONDS + Math.floor(tMs / 1000))
      .u32be((tMs % 1000) * 1000)
      .u32be(packet.frame.length) // incl_len
      .u32be(packet.frame.length) // orig_len: nothing is ever snapped, frames are tiny
      .bytes(packet.frame)
  }

  return writer.finish()
}

/** Byte length `writePcap` will produce, without building the file. */
export function pcapByteLength(packets: readonly PcapPacket[]): number {
  return packets.reduce(
    (total, packet) => total + PCAP_RECORD_HEADER_BYTES + packet.frame.length,
    PCAP_GLOBAL_HEADER_BYTES,
  )
}
