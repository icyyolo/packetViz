/**
 * Protocol dispatch, and `decodeFrame` — the single entry point every view uses.
 *
 * `decodeFrame` is a TOTAL function. For any `Uint8Array`, including empty,
 * truncated, or adversarial input, it:
 *
 *   1. never throws — it returns whatever it could parse plus a `Problem`;
 *   2. never loops forever — every variable-length loop advances by at least one
 *      byte per iteration or bails with a `Problem`;
 *   3. never allocates unbounded — no allocation is sized from an untrusted
 *      length field without first clamping it to the remaining buffer;
 *   4. never reads out of bounds — undecodable trailing bytes become a single
 *      raw `FieldNode`, not a crash.
 *
 * This is not defensive polish: Phase 7 imports .pcap files the user did not
 * create, and Phase 3.5 lets the user edit bytes by hand. `tests/fuzz.property.test.ts`
 * enforces all four clauses.
 *
 * Encapsulation is walked as a chain rather than hard-coded: each layer says
 * where its payload starts and which table identifies it. Ethernet dispatches on
 * EtherType, IPv4 on its protocol number, UDP on a port. That is also what makes
 * "implemented" a derived fact — membership in these tables — rather than a
 * boolean someone has to remember to update.
 */

import type { DecodeResult, DecodedPacket, FieldNode, Problem } from './field.ts'
import { formatHexBytes, hex } from './format.ts'
import { specBytes, specLayout, type FieldSpec, type SpecRow } from './spec.ts'
import { ARP_SPECS, decodeArp } from './protocols/arp.ts'
import { ETHERNET_SPECS, ETHER_TYPE, decodeEthernet, paddingNode } from './protocols/ethernet.ts'
import { DHCP_CLIENT_PORT, DHCP_SERVER_PORT, DHCP_SPECS, decodeDhcp } from './protocols/dhcp.ts'
import { IPV4_SPECS, IP_PROTOCOL, decodeIpv4, type Ipv4Decode } from './protocols/ipv4.ts'
import { UDP_SPECS, decodeUdp, type UdpDecode } from './protocols/udp.ts'

/**
 * What a decoder may need from the layer that carried it. Only UDP uses it, to
 * build the pseudo-header its checksum covers — a real dependency of the wire
 * format, not a convenience.
 */
export type DecodeContext = {
  srcIp: Uint8Array | undefined
  dstIp: Uint8Array | undefined
}

const NO_CONTEXT: DecodeContext = { srcIp: undefined, dstIp: undefined }

export type ProtocolDecoder = (
  frame: Uint8Array,
  offset: number,
  context: DecodeContext,
) => DecodeResult

/** Where a layer's payload lives, and which table identifies it. */
export type Dispatch = {
  table: ReadonlyMap<number, ProtocolEntry>
  /** Candidate keys, in priority order: UDP tries the destination port, then the source. */
  keys: readonly (number | undefined)[]
  /** Used in the "no decoder for ..." message. */
  label: string
  offset: number
  /**
   * How many bytes the enclosing layer says its payload is. Ethernet has no
   * length field so it says "the rest of the frame"; IPv4 and UDP both know,
   * and the difference is exactly the Ethernet padding — which belongs to no
   * protocol and must not be handed to one.
   */
  length: number
  context: DecodeContext
}

export type ProtocolEntry = {
  id: string
  name: string
  decode: ProtocolDecoder
  /** The same table the decoder runs, exposed so reference UI can render the layout without a packet. */
  specs: readonly FieldSpec[]
  /** Where this layer's payload goes, if it carries one we might decode. */
  next?: (result: DecodeResult) => Dispatch
}

const ETHERNET_ENTRY: ProtocolEntry = {
  id: 'eth',
  name: 'Ethernet II',
  decode: (frame) => decodeEthernet(frame),
  specs: ETHERNET_SPECS,
}

const IPV4_ENTRY: ProtocolEntry = {
  id: 'ip',
  name: 'IPv4',
  decode: decodeIpv4,
  specs: IPV4_SPECS,
  next: (result) => {
    const ip = result as Ipv4Decode
    return {
      table: BY_IP_PROTOCOL,
      keys: [ip.protocol],
      label: 'IP protocol',
      offset: ip.payloadOffset,
      length: ip.payloadLength,
      // The addresses travel with the dispatch because UDP's checksum covers
      // them, and UDP cannot see the header they came from.
      context: { srcIp: ip.srcIp, dstIp: ip.dstIp },
    }
  },
}

const UDP_ENTRY: ProtocolEntry = {
  id: 'udp',
  name: 'UDP',
  decode: decodeUdp,
  specs: UDP_SPECS,
  next: (result) => {
    const udp = result as UdpDecode
    return {
      table: BY_UDP_PORT,
      // Either end can be the well-known one. DHCP is the case that needs both:
      // a client sends 68 -> 67 and the server answers 67 -> 68.
      keys: [udp.dstPort, udp.srcPort],
      label: 'UDP port',
      offset: udp.payloadOffset,
      length: udp.payloadLength,
      context: NO_CONTEXT,
    }
  },
}

const DHCP_ENTRY: ProtocolEntry = {
  id: 'dhcp',
  name: 'DHCP (fixed header)',
  decode: decodeDhcp,
  specs: DHCP_SPECS,
}

const ARP_ENTRY: ProtocolEntry = {
  id: 'arp',
  name: 'ARP',
  decode: decodeArp,
  specs: ARP_SPECS,
}

/**
 * EtherType -> decoder. Membership here is what "implemented" means; Phase 8's
 * concept map derives its greyed-out blocks from these tables rather than from a
 * hand-maintained boolean.
 */
export const BY_ETHER_TYPE: ReadonlyMap<number, ProtocolEntry> = new Map([
  [ETHER_TYPE.ARP, ARP_ENTRY],
  [ETHER_TYPE.IPV4, IPV4_ENTRY],
])

export const BY_IP_PROTOCOL: ReadonlyMap<number, ProtocolEntry> = new Map([
  [IP_PROTOCOL.UDP, UDP_ENTRY],
])

export const BY_UDP_PORT: ReadonlyMap<number, ProtocolEntry> = new Map([
  [DHCP_SERVER_PORT, DHCP_ENTRY],
  [DHCP_CLIENT_PORT, DHCP_ENTRY],
])

/** Every protocol this build can decode, keyed by the id its container node carries. */
export const BY_ID: ReadonlyMap<string, ProtocolEntry> = new Map(
  [ETHERNET_ENTRY, ARP_ENTRY, IPV4_ENTRY, UDP_ENTRY, DHCP_ENTRY].map((entry) => [entry.id, entry]),
)

export function decodeFrame(frame: Uint8Array): DecodedPacket {
  const ethernet = decodeEthernet(frame)
  const nodes: FieldNode[] = [...ethernet.nodes]
  const problems: Problem[] = [...ethernet.problems]
  let summary = ethernet.summary
  let offset = ethernet.byteLength

  let dispatch: Dispatch | undefined = {
    table: BY_ETHER_TYPE,
    keys: [ethernet.etherType],
    label: 'EtherType',
    offset,
    // Ethernet carries no length field: everything after the header is payload
    // as far as it is concerned, padding included.
    length: Math.max(0, frame.length - offset),
    context: NO_CONTEXT,
  }

  // Walks down the stack: Ethernet -> IPv4 -> UDP -> DHCP. Bounded by the number
  // of registered protocols, and stopped by the first error, because decoding a
  // payload whose header did not parse would be reading at a made-up offset.
  while (dispatch !== undefined) {
    if (problems.some((problem) => problem.severity === 'error')) break

    const current: Dispatch = dispatch
    const key = current.keys.find(
      (candidate): candidate is number => candidate !== undefined && current.table.has(candidate),
    )
    const entry = key === undefined ? undefined : current.table.get(key)

    if (entry === undefined) {
      const length = Math.min(current.length, Math.max(0, frame.length - current.offset))
      if (length > 0) {
        nodes.push(undecodedNode(frame, current.offset, length, current.label))
        problems.push({
          severity: 'warning',
          message: `No decoder for ${current.label} ${formatKey(current.label, current.keys[0])}; ${length} byte(s) left undecoded`,
          byteStart: current.offset,
          byteLength: length,
        })
        summary = `${summary} (undecoded payload)`
        offset = current.offset + length
      }
      break
    }

    const result = entry.decode(frame, current.offset, current.context)
    nodes.push(...result.nodes)
    problems.push(...result.problems)
    summary = result.summary
    offset = current.offset + result.byteLength
    dispatch = entry.next?.(result)
  }

  if (!problems.some((problem) => problem.severity === 'error')) {
    const padding = paddingNode(frame, offset)
    if (padding !== undefined) nodes.push(padding)
  }

  return { frame, tree: nodes, summary, problems }
}

function formatKey(label: string, key: number | undefined): string {
  if (key === undefined) return '(absent)'
  return label === 'EtherType' ? hex(key, 4) : String(key)
}

/**
 * Undecodable bytes stay linked to the hex view as one raw field, so an
 * unsupported protocol degrades to "here are the bytes" instead of a blank pane.
 */
function undecodedNode(
  frame: Uint8Array,
  offset: number,
  length: number,
  label: string,
): FieldNode {
  const raw = frame.subarray(offset, offset + length)
  return {
    id: 'data',
    name: 'Payload (no decoder)',
    byteStart: offset,
    byteLength: raw.length,
    raw,
    value: formatHexBytes(raw.subarray(0, 16)) + (raw.length > 16 ? ' ...' : ''),
    description: `PacketViz has no decoder registered for this ${label}, so the payload is shown as raw bytes.`,
  }
}

/** A protocol header's generic layout: what the wire format says, with no packet involved. */
export type LayoutSection = {
  id: string
  name: string
  rows: SpecRow[]
  byteLength: number
}

/**
 * The generic layout of the header stack this frame actually carries.
 *
 * Which protocols appear is decided by what the decode found in the frame's own
 * bytes — never by a lesson file — so the reference table shown beside a packet
 * always describes the packet in front of you. The rows themselves are
 * packet-independent: same table, same offsets, whatever the values happen to be.
 */
export function frameLayout(packet: DecodedPacket): LayoutSection[] {
  const sections: LayoutSection[] = []
  for (const node of packet.tree) {
    const entry = BY_ID.get(node.id)
    if (entry === undefined) continue
    sections.push({
      id: entry.id,
      name: entry.name,
      rows: specLayout(entry.specs, node.byteStart),
      byteLength: specBytes(entry.specs),
    })
  }
  return sections
}
