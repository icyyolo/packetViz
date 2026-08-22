/**
 * ICMP, RFC 792 — specifically the two messages `ping` is made of.
 *
 * ICMP is the first protocol in this project with NO length field of its own.
 * An echo message is "everything IPv4 said the payload was", which is why
 * `decodeIcmp` reads `context.length` rather than a header field, and why the
 * checksum it verifies covers bytes the ICMP header never counted. Get that
 * length wrong and the checksum is wrong — which is exactly the dependency
 * `registry.ts` has to thread down from the enclosing IPv4 header.
 *
 * Field ids match tshark's (`icmp.type`, `icmp.ident`, ...) so the differential
 * mapping table stays close to identity.
 */

import { ByteWriter } from '../bytes.ts'
import { icmpChecksum } from '../checksum.ts'
import type { DecodeResult, FieldNode, Problem } from '../field.ts'
import { formatHexBytes, hex } from '../format.ts'
import { enumRender, runSpec, specBytes, type FieldSpec } from '../spec.ts'
import { ETHER_TYPE, encodeEthernet } from './ethernet.ts'
import { IP_PROTOCOL, encodeIpv4 } from './ipv4.ts'

export const ICMP_TYPE = {
  ECHO_REPLY: 0,
  ECHO_REQUEST: 8,
} as const

export const ICMP_TYPE_NAMES: Record<number, string> = {
  [ICMP_TYPE.ECHO_REPLY]: 'Echo (ping) reply',
  3: 'Destination unreachable',
  5: 'Redirect',
  [ICMP_TYPE.ECHO_REQUEST]: 'Echo (ping) request',
  11: 'Time exceeded',
}

export const ICMP_SPECS: readonly FieldSpec[] = [
  {
    id: 'icmp.type',
    name: 'Type',
    bits: 8,
    render: enumRender(ICMP_TYPE_NAMES),
    description:
      'Which ICMP message this is. Type and code together decide the shape of everything after the checksum — ICMP is not one header but a family of them sharing their first four bytes.',
    reference: 'RFC 792',
    values: ICMP_TYPE_NAMES,
  },
  {
    id: 'icmp.code',
    name: 'Code',
    bits: 8,
    render: (_raw, ctx) => String(ctx.num),
    description:
      'Sub-type within the type. Echo request and reply have only code 0; the error messages use it to say which kind of unreachable or which kind of time exceeded.',
    reference: 'RFC 792',
  },
  {
    id: 'icmp.checksum',
    name: 'Checksum',
    bits: 16,
    render: (_raw, ctx) => hex(ctx.num, 4),
    description:
      'One’s-complement checksum over the whole ICMP message, header and data together. Unlike UDP there is no pseudo-header: ICMP is carried by IP and only by IP, so there is no wrong protocol to be delivered to.',
    reference: 'RFC 792',
  },
  {
    id: 'icmp.ident',
    name: 'Identifier',
    bits: 16,
    render: (_raw, ctx) => `${hex(ctx.num, 4)} (${ctx.num})`,
    description:
      'Chosen by the sender and echoed back unchanged, so a host running two pings at once can tell the replies apart. On Linux this is the process id of the ping command.',
    reference: 'RFC 792',
  },
  {
    id: 'icmp.seq',
    name: 'Sequence number',
    bits: 16,
    render: (_raw, ctx) => String(ctx.num),
    description:
      'Counts up one per request, and is echoed back unchanged. It is the whole of ping’s loss detection: a sequence number that never comes back is the packet that was dropped.',
    reference: 'RFC 792',
  },
]

export const ICMP_HEADER_BYTES = specBytes(ICMP_SPECS)

export type IcmpEchoInput = {
  type: number
  identifier: number
  sequence: number
  payload: Uint8Array
}

/** Build an echo message and stamp its checksum over the finished bytes. */
export function encodeIcmpEcho(input: IcmpEchoInput): Uint8Array {
  const message = new ByteWriter()
    .u8(input.type)
    .u8(0) // code: echo request and reply have no sub-types
    .u16be(0) // checksum, stamped below
    .u16be(input.identifier)
    .u16be(input.sequence)
    .bytes(input.payload)
    .finish()

  const checksum = icmpChecksum(message)
  message[2] = checksum >> 8
  message[3] = checksum & 0xff
  return message
}

export type IcmpContext = {
  /** What IPv4 said its payload was. ICMP has no length field of its own. */
  length?: number
}

export function decodeIcmp(
  frame: Uint8Array,
  offset: number,
  context: IcmpContext = {},
): DecodeResult {
  const run = runSpec(ICMP_SPECS, frame, offset)
  const children = [...run.nodes]
  const problems = [...run.problems]
  const truncated = run.problems.length > 0

  const available = Math.max(0, frame.length - offset)
  // Clamped to the frame before use, like every length this decoder is handed.
  const messageLength = Math.min(context.length ?? available, available)
  const type = run.values.get('icmp.type')
  const identifier = run.values.get('icmp.ident')
  const sequence = run.values.get('icmp.seq')

  if (!truncated && messageLength > ICMP_HEADER_BYTES) {
    const dataStart = offset + ICMP_HEADER_BYTES
    const raw = frame.subarray(dataStart, offset + messageLength)
    children.push({
      id: 'icmp.data',
      name: 'Data',
      byteStart: dataStart,
      byteLength: raw.length,
      raw,
      value: formatHexBytes(raw.subarray(0, 16)) + (raw.length > 16 ? ' ...' : ''),
      description:
        'Whatever the sender put here, returned unchanged by the receiver. It carries no meaning to ICMP — its only job is to be echoed, which is what proves the path works in both directions at that size.',
      reference: 'RFC 792',
    })
  }

  if (!truncated) {
    const checksumProblem = verifyChecksum(frame, offset, messageLength, children)
    if (checksumProblem !== undefined) problems.push(checksumProblem)
  }

  const what = ICMP_TYPE_NAMES[type ?? -1] ?? `Type ${type}`
  const summary = truncated
    ? 'ICMP (truncated)'
    : `${what} id=${hex(identifier ?? 0, 4)}, seq=${sequence ?? 0}`

  const node: FieldNode = {
    id: 'icmp',
    name: 'Internet Control Message Protocol',
    byteStart: offset,
    byteLength: Math.min(messageLength, available),
    raw: frame.subarray(offset, offset + Math.min(messageLength, available)),
    value: truncated ? 'truncated' : summary,
    description:
      'IP’s own signalling: the messages a host or router sends when something needs saying about a packet rather than in one. Ping is the harmless half; the error messages are how path MTU discovery and traceroute work.',
    reference: 'RFC 792',
    children,
  }

  return {
    nodes: [node],
    problems,
    summary,
    byteLength: Math.min(messageLength, available),
  }
}

function verifyChecksum(
  frame: Uint8Array,
  offset: number,
  messageLength: number,
  children: FieldNode[],
): Problem | undefined {
  const node = children.find((child) => child.id === 'icmp.checksum')
  if (node === undefined || messageLength < ICMP_HEADER_BYTES) return undefined

  const stored = ((node.raw[0] ?? 0) << 8) | (node.raw[1] ?? 0)
  const expected = icmpChecksum(frame.subarray(offset, offset + messageLength))
  if (stored === expected) {
    node.value = `${hex(stored, 4)} [correct]`
    return undefined
  }

  node.value = `${hex(stored, 4)} [incorrect, should be ${hex(expected, 4)}]`
  return {
    severity: 'warning',
    message: `ICMP checksum is ${hex(stored, 4)} but the message sums to ${hex(expected, 4)}; the receiver would discard it`,
    byteStart: node.byteStart,
    byteLength: node.byteLength,
  }
}

/**
 * Frame builders.
 *
 * Protocol facts decided here: that a ping is an echo request with code 0, that
 * a reply carries the request's identifier, sequence number AND data back
 * unchanged (RFC 792: "the data received in the echo message must be returned"),
 * and that both travel over IPv4 with protocol number 1. A lesson supplies who
 * pings whom and how many times.
 */

export type IcmpEndpoint = { mac: string; ip: string }

/** The identifier and sequence number a ping process picks. */
export type IcmpEcho = { identifier: number; sequence: number }

/**
 * The payload `ping` sends: a fixed ASCII pattern, so a corrupted byte on the
 * wire is visible as a broken alphabet in the hex view rather than as noise.
 * Deliberately not a timestamp — Wireshark tries to read the first eight bytes
 * of a ping payload as one, and a lesson should not depend on that guess.
 */
export const ECHO_PAYLOAD: Uint8Array = Uint8Array.from(
  'abcdefghijklmnopqrstuvwabcdefghi',
  (character) => character.charCodeAt(0),
)

/** RFC 1122 §3.2.1.7 suggests 64; it is what Linux and macOS both send. */
const ECHO_TTL = 64

function echoFrame(
  from: IcmpEndpoint,
  to: IcmpEndpoint,
  type: number,
  echo: IcmpEcho,
): Uint8Array {
  return encodeEthernet({
    dst: to.mac,
    src: from.mac,
    etherType: ETHER_TYPE.IPV4,
    payload: encodeIpv4({
      src: from.ip,
      dst: to.ip,
      protocol: IP_PROTOCOL.ICMP,
      ttl: ECHO_TTL,
      identification: echo.sequence,
      payload: encodeIcmpEcho({
        type,
        identifier: echo.identifier,
        sequence: echo.sequence,
        payload: ECHO_PAYLOAD,
      }),
    }),
  })
}

export function buildIcmpEchoRequestFrame(
  from: IcmpEndpoint,
  to: IcmpEndpoint,
  echo: IcmpEcho,
): Uint8Array {
  return echoFrame(from, to, ICMP_TYPE.ECHO_REQUEST, echo)
}

/** The reply is the request turned around: same identifier, same sequence, same data. */
export function buildIcmpEchoReplyFrame(
  from: IcmpEndpoint,
  to: IcmpEndpoint,
  echo: IcmpEcho,
): Uint8Array {
  return echoFrame(from, to, ICMP_TYPE.ECHO_REPLY, echo)
}
