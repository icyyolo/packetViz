/**
 * Classic libpcap reader — the direction where the bytes are somebody else's.
 *
 * `write.ts` proves our encoder against Wireshark. This module is the opposite
 * bet: a file arrives from a machine we have never seen, written by a tool we
 * did not write, and the decoder has to survive it. So `readPcap` obeys the same
 * totality contract as `decodeFrame`: it never throws, never loops forever, and
 * never allocates from an untrusted length field. A malformed file is a returned
 * message, not an exception, because the only thing worse than a bad capture is
 * a blank page.
 *
 * Two properties of the format make laziness free:
 *
 *   - records are a linked walk, not an index: each is a 16-byte header followed
 *     by `incl_len` bytes, so the header walk touches 16 bytes per packet and
 *     never the frames themselves;
 *   - `frameAt` returns a `subarray`, a view into the file the browser already
 *     loaded, so selecting a packet copies nothing.
 *
 * A 20,000-packet capture therefore costs 20,000 header reads and zero decodes
 * until someone clicks a packet.
 *
 * Reference: https://wiki.wireshark.org/Development/LibpcapFileFormat
 */

import { LINKTYPE_ETHERNET, PCAP_GLOBAL_HEADER_BYTES, PCAP_RECORD_HEADER_BYTES } from './write.ts'

/**
 * Hard cap on records held in memory. The list stays usable and the walk stays
 * bounded; the count of what was skipped is reported so the UI can say so out
 * loud rather than silently truncating the user's file.
 */
export const PCAP_MAX_PACKETS = 5000

/** The four magics a classic pcap can start with: two byte orders x two time resolutions. */
const MAGICS = {
  0xa1b2c3d4: { littleEndian: false, nanosecond: false },
  0xd4c3b2a1: { littleEndian: true, nanosecond: false },
  0xa1b23c4d: { littleEndian: false, nanosecond: true },
  0x4d3cb2a1: { littleEndian: true, nanosecond: true },
} as const satisfies Record<number, { littleEndian: boolean; nanosecond: boolean }>

/** pcapng's Section Header Block. Worth naming: it is what Wireshark saves by default. */
const PCAPNG_MAGIC = 0x0a0d0d0a

/** Enough to explain a rejection. Not a full registry — we decode exactly one of these. */
const LINK_TYPE_NAMES: Record<number, string> = {
  0: 'NULL/loopback',
  1: 'Ethernet',
  101: 'raw IP',
  105: 'IEEE 802.11',
  113: 'Linux cooked capture v1',
  127: 'IEEE 802.11 radiotap',
  276: 'Linux cooked capture v2',
}

export type PcapRecord = {
  index: number
  /** Seconds since the Unix epoch, from the record header. */
  tsSec: number
  /** Sub-second part, normalised to microseconds whatever the file's resolution. */
  tsUsec: number
  /** Bytes actually stored. */
  inclLen: number
  /** Length the frame had on the wire; larger than `inclLen` when the capture was snapped. */
  origLen: number
  /** Absolute offset of the frame within the file. */
  frameOffset: number
}

export type PcapCapture = {
  /** The file itself. Frames are views into this, never copies. */
  bytes: Uint8Array
  byteOrder: 'big-endian' | 'little-endian'
  timeResolution: 'microsecond' | 'nanosecond'
  linkType: number
  snaplen: number
  /** At most `PCAP_MAX_PACKETS` of them. */
  records: PcapRecord[]
  /** How many records the file holds, which may exceed `records.length`. */
  totalRecords: number
  /** Survivable oddities: a truncated last record, trailing bytes, a snaplen overrun. */
  warnings: string[]
}

export type PcapReadResult =
  | { ok: true; capture: PcapCapture }
  | { ok: false; message: string }

export function readPcap(bytes: Uint8Array, maxPackets = PCAP_MAX_PACKETS): PcapReadResult {
  if (bytes.length < PCAP_GLOBAL_HEADER_BYTES) {
    return {
      ok: false,
      message: `This file is ${bytes.length} bytes; a pcap starts with a 24-byte global header.`,
    }
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const magic = view.getUint32(0, false)
  const format = MAGICS[magic as keyof typeof MAGICS] as
    | { littleEndian: boolean; nanosecond: boolean }
    | undefined

  if (format === undefined) {
    if (magic === PCAPNG_MAGIC) {
      return {
        ok: false,
        message:
          'This is a pcapng file, which is what Wireshark saves by default. Re-save it as “Wireshark/tcpdump/… — pcap”, or convert it with: editcap -F pcap in.pcapng out.pcap',
      }
    }
    return {
      ok: false,
      message: `Not a pcap file: it starts with 0x${magic.toString(16).padStart(8, '0')}, and a pcap starts with 0xa1b2c3d4 (or one of its three byte-order/resolution variants).`,
    }
  }

  const { littleEndian, nanosecond } = format
  const linkType = view.getUint32(20, littleEndian)
  if (linkType !== LINKTYPE_ETHERNET) {
    const name = LINK_TYPE_NAMES[linkType]
    return {
      ok: false,
      message: `This capture's link-layer type is ${linkType}${name === undefined ? '' : ` (${name})`}, but PacketViz only decodes Ethernet frames (link-layer type ${LINKTYPE_ETHERNET}).`,
    }
  }

  const snaplen = view.getUint32(16, littleEndian)
  const warnings: string[] = []
  const records: PcapRecord[] = []
  let totalRecords = 0
  let offset = PCAP_GLOBAL_HEADER_BYTES

  // Every iteration advances by at least PCAP_RECORD_HEADER_BYTES, so the walk
  // terminates on any input — including a record claiming a length of zero.
  while (offset + PCAP_RECORD_HEADER_BYTES <= bytes.length) {
    const tsSec = view.getUint32(offset, littleEndian)
    const subSecond = view.getUint32(offset + 4, littleEndian)
    const inclLen = view.getUint32(offset + 8, littleEndian)
    const origLen = view.getUint32(offset + 12, littleEndian)
    const frameOffset = offset + PCAP_RECORD_HEADER_BYTES

    if (frameOffset + inclLen > bytes.length) {
      // Nothing is allocated from `inclLen`; the record is simply refused.
      warnings.push(
        `Record ${totalRecords + 1} claims ${inclLen} bytes but only ${bytes.length - frameOffset} remain — the file ends mid-packet, so it was left out.`,
      )
      break
    }

    if (totalRecords < maxPackets) {
      records.push({
        index: totalRecords,
        tsSec,
        tsUsec: nanosecond ? Math.floor(subSecond / 1000) : subSecond,
        inclLen,
        origLen,
        frameOffset,
      })
    }
    totalRecords += 1
    offset = frameOffset + inclLen
  }

  if (totalRecords === 0) {
    return {
      ok: false,
      message:
        'The pcap header is valid, but the file contains no packet records.',
    }
  }

  const leftover = bytes.length - offset
  if (leftover > 0 && leftover < PCAP_RECORD_HEADER_BYTES) {
    warnings.push(`${leftover} trailing byte(s) after the last record were ignored.`)
  }
  if (records.some((record) => record.origLen > record.inclLen)) {
    warnings.push(
      'Some frames were snapped short during capture (orig_len exceeds incl_len), so their tail bytes are not in the file.',
    )
  }

  return {
    ok: true,
    capture: {
      bytes,
      byteOrder: littleEndian ? 'little-endian' : 'big-endian',
      timeResolution: nanosecond ? 'nanosecond' : 'microsecond',
      linkType,
      snaplen,
      records,
      totalRecords,
      warnings,
    },
  }
}

/** The frame's bytes: a view into the loaded file, never a copy. */
export function frameAt(capture: PcapCapture, record: PcapRecord): Uint8Array {
  return capture.bytes.subarray(record.frameOffset, record.frameOffset + record.inclLen)
}

/** Milliseconds after the capture's first record — what the ladder's y axis wants. */
export function relativeMs(capture: PcapCapture, record: PcapRecord): number {
  const first = capture.records[0]
  if (first === undefined) return 0
  return (record.tsSec - first.tsSec) * 1000 + (record.tsUsec - first.tsUsec) / 1000
}
