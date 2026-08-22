/**
 * IPv4, RFC 791.
 *
 * The first header in this project with sub-byte fields (version and IHL share
 * a byte, flags and fragment offset share two), a length field the rest of the
 * parse depends on, and a checksum. All three are the reason the decoder's
 * totality contract has teeth: IHL and total length are numbers a hostile packet
 * chooses, and both are clamped to what the frame actually contains before
 * anything is read.
 *
 * Field ids match tshark's (`ip.hdr_len`, `ip.frag_offset`, ...) so the
 * differential mapping table stays close to identity.
 */

import { ByteWriter } from '../bytes.ts'
import { ipv4Checksum } from '../checksum.ts'
import type { DecodeResult, FieldNode, Problem } from '../field.ts'
import { formatHexBytes, formatIpv4, hex, parseIpv4 } from '../format.ts'
import { enumRender, runSpec, specBytes, type FieldSpec } from '../spec.ts'

export const IPV4_VERSION = 4
/** Header length with no options: five 32-bit words. */
export const IPV4_MIN_IHL = 5

export const IP_PROTOCOL = {
  ICMP: 1,
  TCP: 6,
  UDP: 17,
} as const

export const IP_PROTOCOL_NAMES: Record<number, string> = {
  [IP_PROTOCOL.ICMP]: 'ICMP',
  [IP_PROTOCOL.TCP]: 'TCP',
  [IP_PROTOCOL.UDP]: 'UDP',
}

const FLAG_NAMES: Record<number, string> = {
  0: 'no flags',
  1: 'More fragments',
  2: "Don't fragment",
  3: "Don't fragment, More fragments",
}

export const IPV4_SPECS: readonly FieldSpec[] = [
  {
    id: 'ip.version',
    name: 'Version',
    bits: 4,
    render: (_raw, ctx) => String(ctx.num),
    description:
      'IP version number. 4 here; the field exists so a receiver can tell an IPv4 packet from an IPv6 one before parsing anything else, which is why it is the very first nibble.',
    reference: 'RFC 791 §3.1',
  },
  {
    id: 'ip.hdr_len',
    name: 'Header length',
    bits: 4,
    render: (_raw, ctx) => `${ctx.num} words (${ctx.num * 4} bytes)`,
    description:
      'Length of this header in 32-bit words, so the minimum is 5 and the maximum is 15 (60 bytes). Anything beyond 5 words is options. This field is what tells the receiver where the payload starts.',
    reference: 'RFC 791 §3.1',
  },
  {
    id: 'ip.dsfield.dscp',
    name: 'Differentiated services code point',
    bits: 6,
    render: (_raw, ctx) => String(ctx.num),
    description:
      'Requested per-hop forwarding behaviour, used for quality of service. 0 is best-effort. These six bits were the old "type of service" field, redefined by RFC 2474.',
    reference: 'RFC 2474 §3',
  },
  {
    id: 'ip.dsfield.ecn',
    name: 'Explicit congestion notification',
    bits: 2,
    render: (_raw, ctx) => String(ctx.num),
    description:
      'Lets a router signal congestion by marking a packet instead of dropping it. 0 means the endpoints are not using ECN.',
    reference: 'RFC 3168 §5',
  },
  {
    id: 'ip.len',
    name: 'Total length',
    bits: 16,
    render: (_raw, ctx) => `${ctx.num} bytes`,
    description:
      'Length of the header plus the payload, in bytes. Note what it does NOT include: the Ethernet header or its padding, which is how a receiver knows where real data stops and padding begins.',
    reference: 'RFC 791 §3.1',
  },
  {
    id: 'ip.id',
    name: 'Identification',
    bits: 16,
    render: (_raw, ctx) => `${ctx.num} (${hex(ctx.num, 4)})`,
    description:
      'Identifies the fragments of one original packet so a receiver can reassemble them. Meaningful only when a packet is fragmented.',
    reference: 'RFC 791 §3.1',
  },
  {
    id: 'ip.flags',
    name: 'Flags',
    bits: 3,
    render: enumRender(FLAG_NAMES, (value) => hex(value, 1)),
    description:
      'Reserved bit, then Don\'t Fragment, then More Fragments. Don\'t Fragment is what makes path MTU discovery work: a router that cannot forward the packet must drop it and report back rather than split it.',
    reference: 'RFC 791 §3.1',
    values: FLAG_NAMES,
  },
  {
    id: 'ip.frag_offset',
    name: 'Fragment offset',
    bits: 13,
    render: (_raw, ctx) => `${ctx.num * 8} bytes`,
    description:
      'Where this fragment sits in the original packet, counted in 8-byte units — which is why 13 bits can address a 65,535-byte packet.',
    reference: 'RFC 791 §3.1',
  },
  {
    id: 'ip.ttl',
    name: 'Time to live',
    bits: 8,
    render: (_raw, ctx) => String(ctx.num),
    description:
      'Decremented by every router that forwards the packet; at zero the packet is discarded and an ICMP error is returned. A hop count, despite the name — it stops packets circulating forever in a routing loop.',
    reference: 'RFC 791 §3.1',
  },
  {
    id: 'ip.proto',
    name: 'Protocol',
    bits: 8,
    render: enumRender(IP_PROTOCOL_NAMES),
    description:
      'What the payload is. 17 is UDP, 6 is TCP, 1 is ICMP. This is IP\'s equivalent of the EtherType, one layer up.',
    reference: 'RFC 791 §3.1',
    values: IP_PROTOCOL_NAMES,
  },
  {
    id: 'ip.checksum',
    name: 'Header checksum',
    bits: 16,
    render: (_raw, ctx) => hex(ctx.num, 4),
    description:
      'One\'s-complement checksum over this header only, not the payload. Every router must recompute it because it decrements the TTL, which is one of the reasons IPv6 dropped the field entirely.',
    reference: 'RFC 791 §3.1',
  },
  {
    id: 'ip.src',
    name: 'Source address',
    bits: 32,
    render: (raw) => formatIpv4(raw),
    description: 'Address of the sender. 0.0.0.0 means "this host, on this network" — a host that does not yet have an address, which is exactly the case DHCP exists to fix.',
    reference: 'RFC 791 §3.1',
  },
  {
    id: 'ip.dst',
    name: 'Destination address',
    bits: 32,
    render: (raw) => formatIpv4(raw),
    description:
      'Address of the intended receiver. 255.255.255.255 is the limited broadcast address: every host on the segment, never forwarded by a router.',
    reference: 'RFC 791 §3.1',
  },
]

export const IPV4_HEADER_BYTES = specBytes(IPV4_SPECS)

export type Ipv4Input = {
  src: string
  dst: string
  protocol: number
  ttl: number
  identification: number
  payload: Uint8Array
}

/**
 * Build a header with no options, then stamp its checksum. The checksum is
 * computed from the finished bytes rather than from the input fields, so the
 * value on the wire is a function of the wire format and not of what we meant
 * to write.
 */
export function encodeIpv4(input: Ipv4Input): Uint8Array {
  const header = new ByteWriter()
    .u8((IPV4_VERSION << 4) | IPV4_MIN_IHL)
    .u8(0) // DSCP + ECN
    .u16be(IPV4_HEADER_BYTES + input.payload.length)
    .u16be(input.identification)
    .u16be(0) // flags + fragment offset
    .u8(input.ttl)
    .u8(input.protocol)
    .u16be(0) // checksum, stamped below
    .bytes(parseIpv4(input.src))
    .bytes(parseIpv4(input.dst))
    .finish()

  const checksum = ipv4Checksum(header)
  header[10] = checksum >> 8
  header[11] = checksum & 0xff

  return new ByteWriter().bytes(header).bytes(input.payload).finish()
}

export type Ipv4Decode = DecodeResult & {
  /** Payload protocol number, or `undefined` if the header was truncated. */
  protocol: number | undefined
  /** Absolute offset of the payload, already clamped to the frame. */
  payloadOffset: number
  /** Payload length, clamped both to the frame and to the header's own claim. */
  payloadLength: number
  /** Addresses the UDP pseudo-header needs; `undefined` when truncated. */
  srcIp: Uint8Array | undefined
  dstIp: Uint8Array | undefined
}

export function decodeIpv4(frame: Uint8Array, offset: number): Ipv4Decode {
  const run = runSpec(IPV4_SPECS, frame, offset)
  const children = [...run.nodes]
  const problems = [...run.problems]
  const truncated = run.problems.length > 0

  const available = Math.max(0, frame.length - offset)
  const version = run.values.get('ip.version')
  const ihl = run.values.get('ip.hdr_len')
  const totalLength = run.values.get('ip.len')

  if (!truncated && version !== IPV4_VERSION) {
    problems.push(spanProblem(children, 'ip.version', `IP version is ${version}, not 4`))
  }

  // The two untrusted lengths. Both are clamped BEFORE anything is read from
  // them, which is clause 3 of the decoder contract: no offset and no length
  // downstream of here can leave the frame.
  const claimedHeader = (ihl ?? IPV4_MIN_IHL) * 4
  if (!truncated && (ihl ?? 0) < IPV4_MIN_IHL) {
    problems.push(
      spanProblem(
        children,
        'ip.hdr_len',
        `Header length ${ihl} is below the minimum of ${IPV4_MIN_IHL} words; a header cannot be shorter than its own fixed fields`,
      ),
    )
  }
  const headerLength = Math.min(Math.max(claimedHeader, IPV4_HEADER_BYTES), available)

  // Anything between the fixed fields and the payload is options. They are not
  // decoded — no lesson uses them — but they are shown, so the hex view never
  // has bytes belonging to nothing.
  if (headerLength > IPV4_HEADER_BYTES) {
    const optionStart = offset + IPV4_HEADER_BYTES
    const raw = frame.subarray(optionStart, offset + headerLength)
    children.push({
      id: 'ip.options',
      name: 'Options',
      byteStart: optionStart,
      byteLength: raw.length,
      raw,
      value: formatHexBytes(raw),
      description:
        'Header options, present because the header length is more than five words. Rare in practice: many networks drop packets that carry them.',
      reference: 'RFC 791 §3.1',
    })
  }

  if (!truncated) {
    const checksumProblem = verifyChecksum(frame, offset, headerLength, children)
    if (checksumProblem !== undefined) problems.push(checksumProblem)
  }

  let payloadLength = Math.max(0, available - headerLength)
  if (!truncated && totalLength !== undefined) {
    if (totalLength > available) {
      problems.push(
        spanProblem(
          children,
          'ip.len',
          `Total length claims ${totalLength} bytes but only ${available} remain in the frame`,
        ),
      )
    } else if (totalLength >= headerLength) {
      // Shorter than the frame is normal: Ethernet padding follows.
      payloadLength = Math.min(payloadLength, totalLength - headerLength)
    }
  }

  const src = run.nodes.find((node) => node.id === 'ip.src')?.raw
  const dst = run.nodes.find((node) => node.id === 'ip.dst')?.raw
  const where = truncated ? '?' : `${formatIpv4(src ?? new Uint8Array())} -> ${formatIpv4(dst ?? new Uint8Array())}`

  const node: FieldNode = {
    id: 'ip',
    name: 'Internet Protocol Version 4',
    byteStart: offset,
    byteLength: Math.min(headerLength, available),
    raw: frame.subarray(offset, offset + Math.min(headerLength, available)),
    value: truncated ? 'truncated' : where,
    description:
      'The internetwork layer: addresses that mean something beyond this segment, and the fields a router needs to forward the packet towards them.',
    reference: 'RFC 791',
    children,
  }

  return {
    nodes: [node],
    problems,
    summary: truncated ? 'IPv4 (truncated)' : where,
    byteLength: Math.min(headerLength, available),
    protocol: truncated ? undefined : run.values.get('ip.proto'),
    payloadOffset: offset + Math.min(headerLength, available),
    payloadLength,
    srcIp: src,
    dstIp: dst,
  }
}

/**
 * Recompute the header checksum and annotate the field with the verdict. A
 * mismatch is a warning rather than an error: the packet is still perfectly
 * readable, and saying which value it should have carried is the useful part —
 * it is what a hand-edited byte produces the moment anyone touches this header.
 */
function verifyChecksum(
  frame: Uint8Array,
  offset: number,
  headerLength: number,
  children: FieldNode[],
): Problem | undefined {
  const node = children.find((child) => child.id === 'ip.checksum')
  if (node === undefined || offset + headerLength > frame.length) return undefined

  const stored = ((node.raw[0] ?? 0) << 8) | (node.raw[1] ?? 0)
  const expected = ipv4Checksum(frame.subarray(offset, offset + headerLength))
  if (stored === expected) {
    node.value = `${hex(stored, 4)} [correct]`
    return undefined
  }

  node.value = `${hex(stored, 4)} [incorrect, should be ${hex(expected, 4)}]`
  return {
    severity: 'warning',
    message: `IPv4 header checksum is ${hex(stored, 4)} but the header sums to ${hex(expected, 4)}; a router would discard this packet`,
    byteStart: node.byteStart,
    byteLength: node.byteLength,
  }
}

/** An error problem pinned to a decoded field's bytes, so it highlights in hex. */
function spanProblem(nodes: readonly FieldNode[], id: string, message: string): Problem {
  const node = nodes.find((candidate) => candidate.id === id)
  return {
    severity: 'error',
    message,
    byteStart: node?.byteStart ?? 0,
    byteLength: node?.byteLength ?? 0,
  }
}
