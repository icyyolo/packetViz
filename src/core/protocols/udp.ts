/**
 * UDP, RFC 768 — the whole protocol is eight bytes.
 *
 * The interesting part is the checksum: it covers a pseudo-header built from the
 * ENCLOSING IPv4 addresses, so UDP cannot verify its own checksum without being
 * told what carried it. That is why `decodeUdp` takes a context argument, and
 * why `registry.ts` has to thread the IP addresses down rather than dispatching
 * blindly on a protocol number.
 */

import { ByteWriter } from '../bytes.ts'
import { udpChecksum } from '../checksum.ts'
import type { DecodeResult, FieldNode, Problem } from '../field.ts'
import { hex, parseIpv4 } from '../format.ts'
import { runSpec, specBytes, type FieldSpec } from '../spec.ts'

export const UDP_PORT_NAMES: Record<number, string> = {
  53: 'DNS',
  67: 'DHCP server',
  68: 'DHCP client',
}

const portRender: FieldSpec['render'] = (_raw, ctx) => {
  const name = UDP_PORT_NAMES[ctx.num]
  return name === undefined ? String(ctx.num) : `${ctx.num} (${name})`
}

export const UDP_SPECS: readonly FieldSpec[] = [
  {
    id: 'udp.srcport',
    name: 'Source port',
    bits: 16,
    render: portRender,
    description:
      'Port the datagram came from, and where a reply should be sent. Together with the addresses and the destination port it identifies the conversation — UDP has no connection, so this tuple is all there is.',
    reference: 'RFC 768',
    values: UDP_PORT_NAMES,
  },
  {
    id: 'udp.dstport',
    name: 'Destination port',
    bits: 16,
    render: portRender,
    description:
      'Which service on the receiving host should get this datagram. DHCP is the unusual case of a protocol with a well-known port at BOTH ends, because the server has to reach a client that does not have an address yet.',
    reference: 'RFC 768',
    values: UDP_PORT_NAMES,
  },
  {
    id: 'udp.length',
    name: 'Length',
    bits: 16,
    render: (_raw, ctx) => `${ctx.num} bytes (header included)`,
    description:
      'Length of the header plus the data, so the minimum legal value is 8. It duplicates information already in the IPv4 total length, a redundancy left over from UDP being designed to run over more than one network layer.',
    reference: 'RFC 768',
  },
  {
    id: 'udp.checksum',
    name: 'Checksum',
    bits: 16,
    render: (_raw, ctx) => hex(ctx.num, 4),
    description:
      'Covers a pseudo-header of the IP addresses and protocol number, then the UDP header and data. Zero means the sender did not compute one, which IPv4 permits and IPv6 does not.',
    reference: 'RFC 768',
  },
]

export const UDP_HEADER_BYTES = specBytes(UDP_SPECS)

export type UdpInput = {
  srcPort: number
  dstPort: number
  srcIp: string
  dstIp: string
  payload: Uint8Array
}

/**
 * The addresses are inputs because the checksum covers them, not because UDP
 * carries them: they come from the IPv4 header this datagram will be placed in.
 */
export function encodeUdp(input: UdpInput): Uint8Array {
  const datagram = new ByteWriter()
    .u16be(input.srcPort)
    .u16be(input.dstPort)
    .u16be(UDP_HEADER_BYTES + input.payload.length)
    .u16be(0) // checksum, stamped below
    .bytes(input.payload)
    .finish()

  const checksum = udpChecksum(parseIpv4(input.srcIp), parseIpv4(input.dstIp), datagram)
  datagram[6] = checksum >> 8
  datagram[7] = checksum & 0xff
  return datagram
}

/** What UDP needs from the layer that carried it in order to check its checksum. */
export type UdpContext = {
  srcIp: Uint8Array | undefined
  dstIp: Uint8Array | undefined
}

export type UdpDecode = DecodeResult & {
  srcPort: number | undefined
  dstPort: number | undefined
  payloadOffset: number
  payloadLength: number
}

export function decodeUdp(frame: Uint8Array, offset: number, context: UdpContext = {
  srcIp: undefined,
  dstIp: undefined,
}): UdpDecode {
  const run = runSpec(UDP_SPECS, frame, offset)
  const problems = [...run.problems]
  const truncated = run.problems.length > 0

  const available = Math.max(0, frame.length - offset)
  const claimed = run.values.get('udp.length') ?? UDP_HEADER_BYTES
  const srcPort = run.values.get('udp.srcport')
  const dstPort = run.values.get('udp.dstport')

  if (!truncated && claimed < UDP_HEADER_BYTES) {
    problems.push({
      severity: 'error',
      message: `UDP length is ${claimed}, but the header alone is ${UDP_HEADER_BYTES} bytes`,
      byteStart: offset + 4,
      byteLength: 2,
    })
  }
  if (!truncated && claimed > available) {
    problems.push({
      severity: 'error',
      message: `UDP length claims ${claimed} bytes but only ${available} remain in the frame`,
      byteStart: offset + 4,
      byteLength: 2,
    })
  }

  // Clamped before use, like every untrusted length in this decoder.
  const datagramLength = Math.min(Math.max(claimed, UDP_HEADER_BYTES), available)
  const payloadOffset = offset + Math.min(UDP_HEADER_BYTES, available)
  const payloadLength = Math.max(0, datagramLength - UDP_HEADER_BYTES)

  if (!truncated) {
    const checksumProblem = verifyChecksum(frame, offset, datagramLength, run.nodes, context)
    if (checksumProblem !== undefined) problems.push(checksumProblem)
  }

  const where = truncated ? '?' : `${srcPort} -> ${dstPort}`
  const node: FieldNode = {
    id: 'udp',
    name: 'User Datagram Protocol',
    byteStart: offset,
    byteLength: Math.min(UDP_HEADER_BYTES, available),
    raw: frame.subarray(offset, offset + Math.min(UDP_HEADER_BYTES, available)),
    value: truncated ? 'truncated' : where,
    description:
      'A datagram service: ports, a length and a checksum, and nothing else. No handshake, no ordering, no retransmission — everything TCP does and UDP does not is the reason it fits in eight bytes.',
    reference: 'RFC 768',
    children: run.nodes,
  }

  return {
    nodes: [node],
    problems,
    summary: truncated ? 'UDP (truncated)' : `UDP ${where}`,
    byteLength: Math.min(UDP_HEADER_BYTES, available),
    srcPort,
    dstPort,
    payloadOffset,
    payloadLength,
  }
}

function verifyChecksum(
  frame: Uint8Array,
  offset: number,
  datagramLength: number,
  nodes: readonly FieldNode[],
  context: UdpContext,
): Problem | undefined {
  const node = nodes.find((child) => child.id === 'udp.checksum')
  if (node === undefined) return undefined

  const stored = ((node.raw[0] ?? 0) << 8) | (node.raw[1] ?? 0)
  if (stored === 0) {
    node.value = '0x0000 [not computed]'
    return undefined
  }

  const { srcIp, dstIp } = context
  if (srcIp === undefined || dstIp === undefined) {
    // Nothing told us what carried this datagram, so the pseudo-header cannot be
    // built. Saying so is honest; claiming the checksum is fine would not be.
    node.value = `${hex(stored, 4)} [unverified: no IP header]`
    return undefined
  }

  const expected = udpChecksum(srcIp, dstIp, frame.subarray(offset, offset + datagramLength))
  if (stored === expected) {
    node.value = `${hex(stored, 4)} [correct]`
    return undefined
  }

  node.value = `${hex(stored, 4)} [incorrect, should be ${hex(expected, 4)}]`
  return {
    severity: 'warning',
    message: `UDP checksum is ${hex(stored, 4)} but the datagram and pseudo-header sum to ${hex(expected, 4)}; the receiver would discard it`,
    byteStart: node.byteStart,
    byteLength: node.byteLength,
  }
}
