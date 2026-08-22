/**
 * Ethernet II framing.
 *
 * Field ids deliberately match tshark's field names (`eth.dst`, `eth.src`,
 * `eth.type`) so the Phase 2 differential mapping table stays close to identity
 * and a divergence is obvious rather than buried in a translation layer.
 */

import { ByteWriter } from '../bytes.ts'
import type { DecodeResult, FieldNode } from '../field.ts'
import { formatHexBytes, formatMac, hex, parseMac } from '../format.ts'
import { enumRender, runSpec, type FieldSpec } from '../spec.ts'

export const ETH_HEADER_BYTES = 14

/**
 * Minimum Ethernet frame size on the wire is 64 bytes including the 4-byte FCS.
 * Captures do not include the FCS, so a captured minimum frame is 60 bytes and
 * short payloads are zero-padded up to it.
 */
export const ETH_MIN_FRAME_BYTES = 60

export const ETHER_TYPE = {
  IPV4: 0x0800,
  ARP: 0x0806,
} as const

export const ETHER_TYPE_NAMES: Record<number, string> = {
  [ETHER_TYPE.IPV4]: 'IPv4',
  [ETHER_TYPE.ARP]: 'ARP',
}

export const BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'

export const ETHERNET_SPECS: readonly FieldSpec[] = [
  {
    id: 'eth.dst',
    name: 'Destination MAC address',
    bits: 48,
    render: (raw) => formatMac(raw),
    description:
      'Hardware address the frame is addressed to. ff:ff:ff:ff:ff:ff is the broadcast address, which every interface on the segment accepts.',
    reference: 'IEEE 802.3 §3.2.5',
  },
  {
    id: 'eth.src',
    name: 'Source MAC address',
    bits: 48,
    render: (raw) => formatMac(raw),
    description: 'Hardware address of the interface that sent the frame.',
    reference: 'IEEE 802.3 §3.2.5',
  },
  {
    id: 'eth.type',
    name: 'EtherType',
    bits: 16,
    render: enumRender(ETHER_TYPE_NAMES, (value) => hex(value, 4)),
    description:
      'Identifies the protocol carried in the payload, which is what tells the receiver whether to hand the frame to ARP or to IP. Values of 0x0600 and above are EtherTypes; smaller values are 802.3 length fields.',
    reference: 'RFC 894',
  },
]

export type EthernetInput = {
  dst: string
  src: string
  etherType: number
  payload: Uint8Array
}

/** Build a frame, padded to the 60-byte captured minimum. */
export function encodeEthernet(input: EthernetInput): Uint8Array {
  return new ByteWriter()
    .bytes(parseMac(input.dst))
    .bytes(parseMac(input.src))
    .u16be(input.etherType)
    .bytes(input.payload)
    .padTo(ETH_MIN_FRAME_BYTES)
    .finish()
}

export type EthernetDecode = DecodeResult & {
  /** `undefined` when the frame was too short to contain the field. */
  etherType: number | undefined
}

export function decodeEthernet(frame: Uint8Array): EthernetDecode {
  const run = runSpec(ETHERNET_SPECS, frame, 0)
  const etherType = run.values.get('eth.type')
  const dst = run.nodes[0]?.value ?? '?'
  const src = run.nodes[1]?.value ?? '?'

  const node: FieldNode = {
    id: 'eth',
    name: 'Ethernet II',
    byteStart: 0,
    byteLength: run.byteLength,
    raw: frame.subarray(0, run.byteLength),
    value: `Src: ${src}, Dst: ${dst}`,
    description:
      'The link-layer frame: 14 bytes of header, then a payload identified by the EtherType.',
    reference: 'RFC 894',
    children: run.nodes,
  }

  return {
    nodes: [node],
    problems: run.problems,
    summary:
      run.problems.length > 0
        ? 'Ethernet II (truncated)'
        : `Ethernet II, Src: ${src}, Dst: ${dst}`,
    byteLength: run.byteLength,
    etherType,
  }
}

/**
 * Bytes after the payload, which belong to no protocol — exposed as their own
 * field so the hex view can say so.
 *
 * Padding and trailer are not the same thing, and a capture from a real network
 * is where the difference shows up. Padding is what brought a short frame up to
 * the 60-byte minimum, so it only deserves the name when the frame is that
 * length. Anything else — a 54-byte frame with twelve zero bytes on the end — is
 * a trailer: bytes the sender or the capture path appended that the minimum
 * cannot explain. Wireshark draws the line in exactly the same place, which is
 * how this was noticed: `tests/import.test.ts` decoded a hand-typed foreign
 * frame and tshark called our "padding" a trailer.
 */
export function paddingNode(frame: Uint8Array, offset: number): FieldNode | undefined {
  if (offset >= frame.length) return undefined
  const raw = frame.subarray(offset)
  const isPadding = frame.length === ETH_MIN_FRAME_BYTES

  return {
    id: isPadding ? 'eth.padding' : 'eth.trailer',
    name: isPadding ? 'Padding' : 'Trailer',
    byteStart: offset,
    byteLength: raw.length,
    raw,
    value: formatHexBytes(raw),
    description: isPadding
      ? `Zero bytes added by the sender so the frame reaches the ${ETH_MIN_FRAME_BYTES}-byte minimum. They are not part of the payload protocol.`
      : `Bytes after the payload that the ${ETH_MIN_FRAME_BYTES}-byte minimum does not account for, so they are a trailer rather than padding. They belong to no protocol here.`,
    reference: 'IEEE 802.3 §4.2.3.3',
  }
}
