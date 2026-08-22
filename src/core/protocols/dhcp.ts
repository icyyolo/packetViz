/**
 * DHCP, RFC 2131 — a BOOTP message (RFC 951) with a magic cookie and a
 * variable-length option list bolted on.
 *
 * This is where the declarative half of the codec stops being enough. The fixed
 * 240-byte header runs through `runSpec` like every other header in the project;
 * the options are a hand-written TLV loop, because their layout is data rather
 * than structure. The loop is where the decoder's totality contract is actually
 * at risk, so it obeys two rules without exception:
 *
 *   - every iteration advances the cursor by at least one byte, or breaks;
 *   - every length byte is checked against the bytes that remain BEFORE it is
 *     used to slice anything.
 *
 * A zero-length option is the concrete trap: naively `offset += 2 + len` with a
 * malformed terminator can leave a parser in place forever. `tests/fuzz.property.test.ts`
 * generates that case explicitly.
 */

import { ByteWriter } from '../bytes.ts'
import type { DecodeResult, FieldNode, Problem } from '../field.ts'
import { formatHexBytes, formatIpv4, formatMac, hex, parseIpv4, parseMac } from '../format.ts'
import { enumRender, runSpec, specBytes, type FieldSpec } from '../spec.ts'
import { BROADCAST_MAC, ETHER_TYPE, encodeEthernet } from './ethernet.ts'
import { IP_PROTOCOL, encodeIpv4 } from './ipv4.ts'
import { encodeUdp } from './udp.ts'

export const DHCP_CLIENT_PORT = 68
export const DHCP_SERVER_PORT = 67

/** RFC 2131 §3: the four bytes that distinguish a DHCP message from plain BOOTP. */
export const DHCP_MAGIC_COOKIE = 0x63825363

export const DHCP_OP = {
  REQUEST: 1,
  REPLY: 2,
} as const

const OP_NAMES: Record<number, string> = {
  [DHCP_OP.REQUEST]: 'Boot Request',
  [DHCP_OP.REPLY]: 'Boot Reply',
}

const HW_TYPE_NAMES: Record<number, string> = { 1: 'Ethernet' }

export const DHCP_HW_TYPE_ETHERNET = 1
export const DHCP_HW_LEN_ETHERNET = 6

/** Option 53 values: which DHCP message this is. */
export const DHCP_MESSAGE_TYPE = {
  DISCOVER: 1,
  OFFER: 2,
  REQUEST: 3,
  DECLINE: 4,
  ACK: 5,
  NAK: 6,
  RELEASE: 7,
  INFORM: 8,
} as const

export const DHCP_MESSAGE_TYPE_NAMES: Record<number, string> = {
  1: 'DISCOVER',
  2: 'OFFER',
  3: 'REQUEST',
  4: 'DECLINE',
  5: 'ACK',
  6: 'NAK',
  7: 'RELEASE',
  8: 'INFORM',
}

export const DHCP_OPTION = {
  PAD: 0,
  SUBNET_MASK: 1,
  ROUTER: 3,
  DNS: 6,
  REQUESTED_IP: 50,
  LEASE_TIME: 51,
  MESSAGE_TYPE: 53,
  SERVER_ID: 54,
  PARAMETER_REQUEST_LIST: 55,
  END: 255,
} as const

export const DHCP_OPTION_NAMES: Record<number, string> = {
  0: 'Padding',
  1: 'Subnet mask',
  3: 'Router',
  6: 'Domain name server',
  50: 'Requested IP address',
  51: 'IP address lease time',
  53: 'DHCP message type',
  54: 'DHCP server identifier',
  55: 'Parameter request list',
  255: 'End',
}

const BROADCAST_FLAG = 0x8000

function asciiOrEmpty(raw: Uint8Array): string {
  const end = raw.indexOf(0)
  const text = Array.from(raw.subarray(0, end < 0 ? raw.length : end), (b) =>
    b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.',
  ).join('')
  return text.length === 0 ? '(empty)' : text
}

/** The fixed BOOTP header plus the magic cookie: 240 bytes, always. */
export const DHCP_SPECS: readonly FieldSpec[] = [
  {
    id: 'dhcp.type',
    name: 'Message op code',
    bits: 8,
    render: enumRender(OP_NAMES),
    description:
      'Whether this is a message towards a server (1) or back towards a client (2). Inherited from BOOTP; the actual DHCP message type lives in option 53, which is why this field is almost never the interesting one.',
    reference: 'RFC 2131 §2',
    values: OP_NAMES,
  },
  {
    id: 'dhcp.hw.type',
    name: 'Hardware type',
    bits: 8,
    render: enumRender(HW_TYPE_NAMES),
    description: 'Link-layer type, using the same number space as ARP. 1 is Ethernet.',
    reference: 'RFC 2131 §2',
    values: HW_TYPE_NAMES,
  },
  {
    id: 'dhcp.hw.len',
    name: 'Hardware address length',
    bits: 8,
    render: (_raw, ctx) => `${ctx.num} bytes`,
    description: 'Length of the client hardware address. 6 for Ethernet.',
    reference: 'RFC 2131 §2',
  },
  {
    id: 'dhcp.hops',
    name: 'Hops',
    bits: 8,
    render: (_raw, ctx) => String(ctx.num),
    description:
      'Incremented by each relay agent that forwards the message. A client sends zero; a non-zero value means the server is not on the client\'s own segment.',
    reference: 'RFC 2131 §2',
  },
  {
    id: 'dhcp.id',
    name: 'Transaction ID',
    bits: 32,
    render: (_raw, ctx) => hex(ctx.num, 8),
    description:
      'Random number chosen by the client, echoed by the server, tying the four messages of a DORA exchange together. It is the only thing that does: DHCP runs over UDP, which has no connection.',
    reference: 'RFC 2131 §2',
  },
  {
    id: 'dhcp.secs',
    name: 'Seconds elapsed',
    bits: 16,
    render: (_raw, ctx) => `${ctx.num} seconds`,
    description:
      'How long the client has been trying to acquire an address. Backup DHCP servers use it to decide when to answer instead of the primary.',
    reference: 'RFC 2131 §2',
  },
  {
    id: 'dhcp.flags',
    name: 'Flags',
    bits: 16,
    render: (_raw, ctx) =>
      `${hex(ctx.num, 4)} (${(ctx.num & BROADCAST_FLAG) === 0 ? 'unicast' : 'broadcast'})`,
    description:
      'Only the top bit is defined: the broadcast flag. A client with no address yet may be unable to receive a unicast reply, so it asks the server to broadcast the answer instead.',
    reference: 'RFC 2131 §2',
  },
  {
    id: 'dhcp.ip.client',
    name: 'Client IP address',
    bits: 32,
    render: (raw) => formatIpv4(raw),
    description:
      'Filled in only by a client that already has a working address and is renewing it. 0.0.0.0 during the initial exchange.',
    reference: 'RFC 2131 §2',
  },
  {
    id: 'dhcp.ip.your',
    name: 'Your (client) IP address',
    bits: 32,
    render: (raw) => formatIpv4(raw),
    description:
      'The address the server is offering or confirming. This is the field the whole protocol exists to fill in.',
    reference: 'RFC 2131 §2',
  },
  {
    id: 'dhcp.ip.server',
    name: 'Next server IP address',
    bits: 32,
    render: (raw) => formatIpv4(raw),
    description:
      'Next server in a boot sequence — a TFTP server, for network booting. Not the DHCP server\'s own address, which is option 54 instead.',
    reference: 'RFC 2131 §2',
  },
  {
    id: 'dhcp.ip.relay',
    name: 'Relay agent IP address',
    bits: 32,
    render: (raw) => formatIpv4(raw),
    description:
      'Filled in by a relay agent so the server knows which subnet the request came from, and where to send the answer back. 0.0.0.0 when client and server share a segment.',
    reference: 'RFC 2131 §2',
  },
  {
    id: 'dhcp.hw.mac_addr',
    name: 'Client MAC address',
    bits: 48,
    render: (raw) => formatMac(raw),
    description:
      'How the server identifies the client before it has an IP address, and what it keys the lease on.',
    reference: 'RFC 2131 §2',
  },
  {
    id: 'dhcp.hw.addr_padding',
    name: 'Client hardware address padding',
    bits: 80,
    render: (raw) => formatHexBytes(raw),
    description:
      'The client hardware address field is a fixed 16 bytes; an Ethernet address uses 6 of them and the rest are zero.',
    reference: 'RFC 2131 §2',
  },
  {
    id: 'dhcp.server',
    name: 'Server host name',
    bits: 512,
    render: (raw) => asciiOrEmpty(raw),
    description:
      'Optional server name, 64 bytes of it. Usually empty — a reminder that this header was designed for booting diskless workstations in 1985.',
    reference: 'RFC 2131 §2',
  },
  {
    id: 'dhcp.file',
    name: 'Boot file name',
    bits: 1024,
    render: (raw) => asciiOrEmpty(raw),
    description:
      'Optional boot file name, 128 bytes. Empty in an ordinary address exchange; between them, these two fields are 192 of the header\'s 240 bytes.',
    reference: 'RFC 2131 §2',
  },
  {
    id: 'dhcp.cookie',
    name: 'Magic cookie',
    bits: 32,
    render: (_raw, ctx) => hex(ctx.num, 8),
    description:
      'The four bytes 0x63825363, at a fixed offset of 236. Their presence is what tells a receiver that the bytes after them are DHCP options rather than BOOTP\'s vendor-specific area.',
    reference: 'RFC 2131 §3',
  },
]

export const DHCP_FIXED_BYTES = specBytes(DHCP_SPECS)

export type DhcpOptionInput = { code: number; value: Uint8Array }

export type DhcpInput = {
  op: number
  xid: number
  secs: number
  broadcast: boolean
  clientIp: string
  yourIp: string
  serverIp: string
  relayIp: string
  clientMac: string
  options: readonly DhcpOptionInput[]
}

/** Option payload helpers, so an encoder writes values rather than bytes. */
export const optionIpv4 = (ip: string): Uint8Array => parseIpv4(ip)
export const optionU8 = (value: number): Uint8Array => Uint8Array.from([value & 0xff])
export const optionU32 = (value: number): Uint8Array =>
  Uint8Array.from([(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff])
export const optionCodes = (codes: readonly number[]): Uint8Array =>
  Uint8Array.from(codes, (code) => code & 0xff)

export function encodeDhcp(input: DhcpInput): Uint8Array {
  const writer = new ByteWriter()
    .u8(input.op)
    .u8(DHCP_HW_TYPE_ETHERNET)
    .u8(DHCP_HW_LEN_ETHERNET)
    .u8(0) // hops: a client sends zero
    .u32be(input.xid)
    .u16be(input.secs)
    .u16be(input.broadcast ? BROADCAST_FLAG : 0)
    .bytes(parseIpv4(input.clientIp))
    .bytes(parseIpv4(input.yourIp))
    .bytes(parseIpv4(input.serverIp))
    .bytes(parseIpv4(input.relayIp))
    .bytes(parseMac(input.clientMac))
    .zeros(10) // rest of the 16-byte hardware address field
    .zeros(64) // sname
    .zeros(128) // file
    .u32be(DHCP_MAGIC_COOKIE)

  for (const option of input.options) {
    writer.u8(option.code).u8(option.value.length).bytes(option.value)
  }
  return writer.u8(DHCP_OPTION.END).finish()
}

export type DhcpDecode = DecodeResult & {
  /** Option 53's value, which is what a summary line actually reports. */
  messageType: number | undefined
}

export function decodeDhcp(frame: Uint8Array, offset: number): DhcpDecode {
  const run = runSpec(DHCP_SPECS, frame, offset)
  const problems = [...run.problems]
  const truncated = run.problems.length > 0
  const children = [...run.nodes]

  const cookie = run.values.get('dhcp.cookie')
  if (!truncated && cookie !== DHCP_MAGIC_COOKIE) {
    const node = children.find((child) => child.id === 'dhcp.cookie')
    problems.push({
      severity: 'error',
      message: `Magic cookie is ${hex(cookie ?? 0, 8)}, not ${hex(DHCP_MAGIC_COOKIE, 8)}; these bytes are not DHCP options`,
      byteStart: node?.byteStart ?? offset,
      byteLength: node?.byteLength ?? 0,
    })
  }

  const optionStart = offset + DHCP_FIXED_BYTES
  const options = truncated || cookie !== DHCP_MAGIC_COOKIE
    ? { nodes: [], problems: [], end: optionStart, messageType: undefined }
    : decodeOptions(frame, optionStart)

  children.push(...options.nodes)
  problems.push(...options.problems)

  const byteLength = Math.max(0, Math.min(options.end, frame.length) - offset)
  const summary = truncated
    ? 'DHCP (truncated)'
    : `DHCP ${DHCP_MESSAGE_TYPE_NAMES[options.messageType ?? -1] ?? 'message'}`

  const node: FieldNode = {
    id: 'dhcp',
    name: 'Dynamic Host Configuration Protocol',
    byteStart: offset,
    byteLength,
    raw: frame.subarray(offset, offset + byteLength),
    value: summary,
    description:
      'Hands a client an address, a subnet mask, a gateway and a lease on all of it — over UDP, before the client has an address to be reached at.',
    reference: 'RFC 2131',
    children,
  }

  return { nodes: [node], problems, summary, byteLength, messageType: options.messageType }
}

type OptionRun = {
  nodes: FieldNode[]
  problems: Problem[]
  /** Absolute offset just past the last option consumed. */
  end: number
  messageType: number | undefined
}

/**
 * The TLV loop. Reads until the End option, the frame runs out, or something
 * does not add up — and advances at least one byte on every path that continues.
 *
 * Repeated option codes produce repeated field ids. That is malformed input
 * rather than a case to design for: the tree still shows every occurrence, and
 * only lookups by id (the deep-link form `?f=dhcp.opt.53`) resolve to the first.
 */
function decodeOptions(frame: Uint8Array, start: number): OptionRun {
  const nodes: FieldNode[] = []
  const problems: Problem[] = []
  let messageType: number | undefined
  let cursor = start

  while (cursor < frame.length) {
    const code = frame[cursor]
    if (code === undefined) break

    if (code === DHCP_OPTION.PAD) {
      nodes.push(simpleOption(frame, cursor, code, 'Padding to a word boundary. One byte, no length, no value.'))
      cursor += 1
      continue
    }
    if (code === DHCP_OPTION.END) {
      nodes.push(simpleOption(frame, cursor, code, 'Marks the end of the option list. Everything after it is padding.'))
      cursor += 1
      break
    }

    const length = frame[cursor + 1]
    if (length === undefined) {
      problems.push({
        severity: 'error',
        message: `Option ${code} has no length byte: the frame ends at ${frame.length}`,
        byteStart: cursor,
        byteLength: frame.length - cursor,
      })
      break
    }

    const valueStart = cursor + 2
    const remaining = frame.length - valueStart
    if (length > remaining) {
      problems.push({
        severity: 'error',
        message: `Option ${code} (${optionName(code)}) declares ${length} byte(s) of value but only ${Math.max(0, remaining)} remain`,
        byteStart: cursor,
        byteLength: Math.max(0, frame.length - cursor),
      })
      break
    }

    const value = frame.subarray(valueStart, valueStart + length)
    if (code === DHCP_OPTION.MESSAGE_TYPE && length >= 1) messageType = value[0]
    nodes.push(tlvOption(frame, cursor, code, length, value))

    // Always forward by the full TLV, so a zero-length option still advances.
    cursor = valueStart + length
  }

  return { nodes, problems, end: cursor, messageType }
}

function optionName(code: number): string {
  return DHCP_OPTION_NAMES[code] ?? 'unknown option'
}

/** PAD and END: one byte, no length, no value. */
function simpleOption(frame: Uint8Array, offset: number, code: number, description: string): FieldNode {
  return {
    id: `dhcp.opt.${code}`,
    name: `Option ${code}: ${optionName(code)}`,
    byteStart: offset,
    byteLength: 1,
    raw: frame.subarray(offset, offset + 1),
    value: optionName(code),
    description,
    reference: 'RFC 2132 §3',
  }
}

function tlvOption(
  frame: Uint8Array,
  offset: number,
  code: number,
  length: number,
  value: Uint8Array,
): FieldNode {
  const id = `dhcp.opt.${code}`
  const rendered = renderOptionValue(code, value)

  const children: FieldNode[] = [
    {
      id: `${id}.code`,
      name: 'Option code',
      byteStart: offset,
      byteLength: 1,
      raw: frame.subarray(offset, offset + 1),
      value: `${code} (${optionName(code)})`,
      description: 'Identifies the option. The registry of codes is RFC 2132.',
      reference: 'RFC 2132 §2',
    },
    {
      id: `${id}.len`,
      name: 'Length',
      byteStart: offset + 1,
      byteLength: 1,
      raw: frame.subarray(offset + 1, offset + 2),
      value: `${length} bytes`,
      description:
        'Length of the value that follows, which is what lets a receiver skip an option it does not understand instead of giving up on the packet.',
      reference: 'RFC 2132 §2',
    },
  ]

  if (length > 0) {
    children.push({
      id: `${id}.value`,
      name: 'Value',
      byteStart: offset + 2,
      byteLength: length,
      raw: value,
      value: rendered,
      description: optionDescription(code),
      reference: 'RFC 2132 §3',
    })
  }

  return {
    id,
    name: `Option ${code}: ${optionName(code)}`,
    byteStart: offset,
    byteLength: 2 + length,
    raw: frame.subarray(offset, offset + 2 + length),
    value: rendered,
    description: optionDescription(code),
    reference: 'RFC 2132 §3',
    children,
  }
}

function renderOptionValue(code: number, value: Uint8Array): string {
  switch (code) {
    case DHCP_OPTION.MESSAGE_TYPE: {
      const type = value[0] ?? -1
      return `${type} (${DHCP_MESSAGE_TYPE_NAMES[type] ?? 'unknown'})`
    }
    case DHCP_OPTION.LEASE_TIME: {
      const seconds = readU32(value)
      return seconds === undefined ? formatHexBytes(value) : `${seconds} seconds`
    }
    case DHCP_OPTION.SUBNET_MASK:
    case DHCP_OPTION.REQUESTED_IP:
    case DHCP_OPTION.SERVER_ID:
    case DHCP_OPTION.ROUTER:
    case DHCP_OPTION.DNS:
      return value.length % 4 === 0 && value.length > 0
        ? addressList(value)
        : formatHexBytes(value)
    case DHCP_OPTION.PARAMETER_REQUEST_LIST:
      return Array.from(value, (requested) => `${requested} (${optionName(requested)})`).join(', ')
    default:
      return formatHexBytes(value)
  }
}

function addressList(value: Uint8Array): string {
  const addresses: string[] = []
  for (let i = 0; i + 4 <= value.length; i += 4) addresses.push(formatIpv4(value.subarray(i, i + 4)))
  return addresses.join(', ')
}

function readU32(value: Uint8Array): number | undefined {
  if (value.length !== 4) return undefined
  return ((value[0] ?? 0) * 0x1000000 + ((value[1] ?? 0) << 16) + ((value[2] ?? 0) << 8) + (value[3] ?? 0))
}

function optionDescription(code: number): string {
  switch (code) {
    case DHCP_OPTION.MESSAGE_TYPE:
      return 'Which of the eight DHCP messages this is. Present in every DHCP packet — it is what separates DHCP from the BOOTP header it is carried in.'
    case DHCP_OPTION.SERVER_ID:
      return 'Address of the server that sent this message. A client that received offers from several servers puts the chosen one here so the others know they were declined.'
    case DHCP_OPTION.LEASE_TIME:
      return 'How long the client may use the address, in seconds. A lease, not a grant: the client must renew it or lose it.'
    case DHCP_OPTION.REQUESTED_IP:
      return 'The address the client is asking for — the one it was offered, or the one it held before rebooting.'
    case DHCP_OPTION.PARAMETER_REQUEST_LIST:
      return 'The configuration the client would like to be told, by option code. The server answers with what it has.'
    case DHCP_OPTION.SUBNET_MASK:
      return 'Which part of the address identifies the network, and therefore which destinations the host can reach without a router.'
    case DHCP_OPTION.ROUTER:
      return 'Default gateway (or gateways, in preference order) for this subnet.'
    case DHCP_OPTION.DNS:
      return 'Name servers the client should use, in preference order.'
    default:
      return 'Option carried in the DHCP option list. This decoder shows its raw bytes; RFC 2132 registers the meaning.'
  }
}

/**
 * Frame builders.
 *
 * Like the ARP builders, these live in `core` because everything they decide is
 * a protocol fact: that a client with no address sends from 0.0.0.0:68 to
 * 255.255.255.255:67, that it sets the broadcast flag so a server can answer a
 * host that cannot yet receive unicast, that a server therefore replies to the
 * broadcast address too, that a REQUEST names both the address it wants and the
 * server it accepted it from. A lesson supplies who the client is, what address
 * is offered, and how long the lease runs.
 */

export type DhcpClient = { mac: string }

export type DhcpLease = {
  serverMac: string
  serverIp: string
  clientIp: string
  subnetMask: string
  router: string
  dns: string
  leaseSeconds: number
}

const UNSPECIFIED_IP = '0.0.0.0'
const BROADCAST_IP = '255.255.255.255'
/** RFC 2131 §4.1: a client's messages go out with a TTL that cannot be routed away. */
const CLIENT_TTL = 255
const SERVER_TTL = 64

/** The configuration a client asks to be told, by option code. */
const REQUESTED_PARAMETERS = [DHCP_OPTION.SUBNET_MASK, DHCP_OPTION.ROUTER, DHCP_OPTION.DNS]

type FrameParts = {
  ethDst: string
  ethSrc: string
  srcIp: string
  dstIp: string
  srcPort: number
  dstPort: number
  ttl: number
  identification: number
  dhcp: Uint8Array
}

function frame(parts: FrameParts): Uint8Array {
  const udp = encodeUdp({
    srcPort: parts.srcPort,
    dstPort: parts.dstPort,
    srcIp: parts.srcIp,
    dstIp: parts.dstIp,
    payload: parts.dhcp,
  })
  return encodeEthernet({
    dst: parts.ethDst,
    src: parts.ethSrc,
    etherType: ETHER_TYPE.IPV4,
    payload: encodeIpv4({
      src: parts.srcIp,
      dst: parts.dstIp,
      protocol: IP_PROTOCOL.UDP,
      ttl: parts.ttl,
      identification: parts.identification,
      payload: udp,
    }),
  })
}

/** Client -> everyone: "is there a DHCP server?" */
export function buildDhcpDiscoverFrame(client: DhcpClient, xid: number): Uint8Array {
  return frame({
    ethDst: BROADCAST_MAC,
    ethSrc: client.mac,
    srcIp: UNSPECIFIED_IP,
    dstIp: BROADCAST_IP,
    srcPort: DHCP_CLIENT_PORT,
    dstPort: DHCP_SERVER_PORT,
    ttl: CLIENT_TTL,
    identification: 1,
    dhcp: encodeDhcp({
      op: DHCP_OP.REQUEST,
      xid,
      secs: 0,
      broadcast: true,
      clientIp: UNSPECIFIED_IP,
      yourIp: UNSPECIFIED_IP,
      serverIp: UNSPECIFIED_IP,
      relayIp: UNSPECIFIED_IP,
      clientMac: client.mac,
      options: [
        { code: DHCP_OPTION.MESSAGE_TYPE, value: optionU8(DHCP_MESSAGE_TYPE.DISCOVER) },
        { code: DHCP_OPTION.PARAMETER_REQUEST_LIST, value: optionCodes(REQUESTED_PARAMETERS) },
      ],
    }),
  })
}

/** Server -> everyone: "you may have this address". Broadcast, because the client's flag asked for it. */
export function buildDhcpOfferFrame(client: DhcpClient, lease: DhcpLease, xid: number): Uint8Array {
  return frame({
    ethDst: BROADCAST_MAC,
    ethSrc: lease.serverMac,
    srcIp: lease.serverIp,
    dstIp: BROADCAST_IP,
    srcPort: DHCP_SERVER_PORT,
    dstPort: DHCP_CLIENT_PORT,
    ttl: SERVER_TTL,
    identification: 2,
    dhcp: encodeDhcp({
      op: DHCP_OP.REPLY,
      xid,
      secs: 0,
      broadcast: true,
      clientIp: UNSPECIFIED_IP,
      yourIp: lease.clientIp,
      serverIp: UNSPECIFIED_IP,
      relayIp: UNSPECIFIED_IP,
      clientMac: client.mac,
      options: [
        { code: DHCP_OPTION.MESSAGE_TYPE, value: optionU8(DHCP_MESSAGE_TYPE.OFFER) },
        { code: DHCP_OPTION.SERVER_ID, value: optionIpv4(lease.serverIp) },
        { code: DHCP_OPTION.LEASE_TIME, value: optionU32(lease.leaseSeconds) },
        { code: DHCP_OPTION.SUBNET_MASK, value: optionIpv4(lease.subnetMask) },
        { code: DHCP_OPTION.ROUTER, value: optionIpv4(lease.router) },
        { code: DHCP_OPTION.DNS, value: optionIpv4(lease.dns) },
      ],
    }),
  })
}

/**
 * Client -> everyone: "I accept that offer, from that server."
 *
 * Still broadcast, and still from 0.0.0.0: the client has not configured the
 * address yet. Naming the server in option 54 is how the offers it did not take
 * get released.
 */
export function buildDhcpRequestFrame(client: DhcpClient, lease: DhcpLease, xid: number): Uint8Array {
  return frame({
    ethDst: BROADCAST_MAC,
    ethSrc: client.mac,
    srcIp: UNSPECIFIED_IP,
    dstIp: BROADCAST_IP,
    srcPort: DHCP_CLIENT_PORT,
    dstPort: DHCP_SERVER_PORT,
    ttl: CLIENT_TTL,
    identification: 3,
    dhcp: encodeDhcp({
      op: DHCP_OP.REQUEST,
      xid,
      secs: 0,
      broadcast: true,
      clientIp: UNSPECIFIED_IP,
      yourIp: UNSPECIFIED_IP,
      serverIp: UNSPECIFIED_IP,
      relayIp: UNSPECIFIED_IP,
      clientMac: client.mac,
      options: [
        { code: DHCP_OPTION.MESSAGE_TYPE, value: optionU8(DHCP_MESSAGE_TYPE.REQUEST) },
        { code: DHCP_OPTION.REQUESTED_IP, value: optionIpv4(lease.clientIp) },
        { code: DHCP_OPTION.SERVER_ID, value: optionIpv4(lease.serverIp) },
        { code: DHCP_OPTION.PARAMETER_REQUEST_LIST, value: optionCodes(REQUESTED_PARAMETERS) },
      ],
    }),
  })
}

/** Server -> everyone: "confirmed, and here is the rest of your configuration." */
export function buildDhcpAckFrame(client: DhcpClient, lease: DhcpLease, xid: number): Uint8Array {
  return frame({
    ethDst: BROADCAST_MAC,
    ethSrc: lease.serverMac,
    srcIp: lease.serverIp,
    dstIp: BROADCAST_IP,
    srcPort: DHCP_SERVER_PORT,
    dstPort: DHCP_CLIENT_PORT,
    ttl: SERVER_TTL,
    identification: 4,
    dhcp: encodeDhcp({
      op: DHCP_OP.REPLY,
      xid,
      secs: 0,
      broadcast: true,
      clientIp: UNSPECIFIED_IP,
      yourIp: lease.clientIp,
      serverIp: UNSPECIFIED_IP,
      relayIp: UNSPECIFIED_IP,
      clientMac: client.mac,
      options: [
        { code: DHCP_OPTION.MESSAGE_TYPE, value: optionU8(DHCP_MESSAGE_TYPE.ACK) },
        { code: DHCP_OPTION.SERVER_ID, value: optionIpv4(lease.serverIp) },
        { code: DHCP_OPTION.LEASE_TIME, value: optionU32(lease.leaseSeconds) },
        { code: DHCP_OPTION.SUBNET_MASK, value: optionIpv4(lease.subnetMask) },
        { code: DHCP_OPTION.ROUTER, value: optionIpv4(lease.router) },
        { code: DHCP_OPTION.DNS, value: optionIpv4(lease.dns) },
      ],
    }),
  })
}
