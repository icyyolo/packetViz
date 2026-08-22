/**
 * TCP, RFC 9293 — the three segments of a connection setup.
 *
 * This is the first protocol here whose interesting state lives BETWEEN packets
 * rather than inside one. A sequence number means nothing on its own; it means
 * something relative to the number the other end sent in its SYN. That is why
 * the ladder diagram earns its place on this lesson and not on the others.
 *
 * Two deliberate decisions follow from the single-buffer invariant:
 *
 *   - The decoder reports the sequence number ON THE WIRE. Wireshark, by
 *     default, subtracts each side's initial sequence number and shows a
 *     relative one — which is a projection over the whole capture, not a fact in
 *     the packet. Our differential therefore maps `tcp.seq` to tshark's
 *     `tcp.seq_raw`, and the lesson narration explains the difference rather
 *     than the decoder hiding it.
 *   - Like ICMP, TCP has no length field. The payload length is IPv4's total
 *     length minus two header lengths, and the checksum covers exactly that many
 *     bytes, so `context.length` is load-bearing rather than an optimisation.
 *
 * Field ids match tshark's where tshark has one for the same wire bits.
 */

import { ByteWriter } from '../bytes.ts'
import { tcpChecksum } from '../checksum.ts'
import type { DecodeResult, FieldNode, Problem } from '../field.ts'
import { formatHexBytes, hex, parseIpv4 } from '../format.ts'
import { runSpec, specBytes, type FieldSpec } from '../spec.ts'
import { ETHER_TYPE, encodeEthernet } from './ethernet.ts'
import { IP_PROTOCOL, encodeIpv4 } from './ipv4.ts'

/** Well-known destination ports a lesson might connect to. */
export const TCP_PORT = {
  HTTP: 80,
} as const

export const TCP_PORT_NAMES: Record<number, string> = {
  [TCP_PORT.HTTP]: 'HTTP',
  443: 'HTTPS',
}

/** The eight flag bits, as masks within the low byte of the flags field. */
export const TCP_FLAG = {
  FIN: 0x01,
  SYN: 0x02,
  RST: 0x04,
  PSH: 0x08,
  ACK: 0x10,
  URG: 0x20,
  ECE: 0x40,
  CWR: 0x80,
} as const

/** Option kinds, RFC 9293 §3.2 and RFC 7323. */
export const TCP_OPTION = {
  END: 0,
  NOP: 1,
  MSS: 2,
  WINDOW_SCALE: 3,
  SACK_PERMITTED: 4,
} as const

export const TCP_OPTION_NAMES: Record<number, string> = {
  [TCP_OPTION.END]: 'End of option list',
  [TCP_OPTION.NOP]: 'No-Operation',
  [TCP_OPTION.MSS]: 'Maximum segment size',
  [TCP_OPTION.WINDOW_SCALE]: 'Window scale',
  [TCP_OPTION.SACK_PERMITTED]: 'SACK permitted',
  5: 'SACK',
  8: 'Timestamps',
}

const portRender: FieldSpec['render'] = (_raw, ctx) => {
  const name = TCP_PORT_NAMES[ctx.num]
  return name === undefined ? String(ctx.num) : `${ctx.num} (${name})`
}

/** A one-bit flag: "Set" / "Not set", the way a flag reads in a field tree. */
function flagSpec(id: string, name: string, description: string): FieldSpec {
  return {
    id,
    name,
    bits: 1,
    render: (_raw, ctx) => (ctx.num === 1 ? 'Set' : 'Not set'),
    description,
    reference: 'RFC 9293 §3.1',
    values: { 0: 'Not set', 1: 'Set' },
  }
}

export const TCP_SPECS: readonly FieldSpec[] = [
  {
    id: 'tcp.srcport',
    name: 'Source port',
    bits: 16,
    render: portRender,
    description:
      'Port the connection came from. Together with the destination port and the two IP addresses it forms the four-tuple that IS the connection — TCP has no other name for it.',
    reference: 'RFC 9293 §3.1',
    values: TCP_PORT_NAMES,
  },
  {
    id: 'tcp.dstport',
    name: 'Destination port',
    bits: 16,
    render: portRender,
    description:
      'Which service is being connected to. A client picks an ephemeral source port and a well-known destination port; the server answers with them swapped.',
    reference: 'RFC 9293 §3.1',
    values: TCP_PORT_NAMES,
  },
  {
    id: 'tcp.seq',
    name: 'Sequence number',
    bits: 32,
    render: (_raw, ctx) => `${ctx.num >>> 0}`,
    description:
      'Position of this segment’s first byte in the sender’s stream. The first one is chosen at random, not zero, so that a segment from an old connection cannot be mistaken for one in this connection. Wireshark shows a relative number by default; this is the value actually on the wire.',
    reference: 'RFC 9293 §3.1',
  },
  {
    id: 'tcp.ack',
    name: 'Acknowledgement number',
    bits: 32,
    render: (_raw, ctx) => `${ctx.num >>> 0}`,
    description:
      'The next sequence number the sender expects to receive — everything below it has arrived. Meaningful only when the ACK flag is set, which is every segment after the first.',
    reference: 'RFC 9293 §3.1',
  },
  {
    id: 'tcp.hdr_len',
    name: 'Data offset',
    bits: 4,
    render: (_raw, ctx) => `${ctx.num} words (${ctx.num * 4} bytes)`,
    description:
      'Length of this header in 32-bit words, so the minimum is 5 and anything beyond that is options. TCP needs it because, unlike UDP, its header is not a fixed size.',
    reference: 'RFC 9293 §3.1',
  },
  {
    id: 'tcp.flags.res',
    name: 'Reserved',
    bits: 3,
    render: (_raw, ctx) => (ctx.num === 0 ? 'Not set' : `Set (${ctx.num})`),
    description:
      'Reserved for future use and sent as zero. Middleboxes that rejected packets with these bits set are a large part of why TCP is so hard to extend.',
    reference: 'RFC 9293 §3.1',
  },
  flagSpec(
    'tcp.flags.ns',
    'Nonce',
    'An ECN nonce bit from RFC 3540, an experiment that was never deployed and has since been reclassified as reserved. Wireshark still names it, so it is named here.',
  ),
  flagSpec(
    'tcp.flags.cwr',
    'Congestion Window Reduced',
    'Set by a sender to tell the other end it has reacted to a congestion signal. Part of ECN, which lets a router mark a packet instead of dropping it.',
  ),
  flagSpec(
    'tcp.flags.ecn',
    'ECN-Echo',
    'Echoes back the fact that a router marked a packet as congested. In a SYN it means something different: "I support ECN".',
  ),
  flagSpec(
    'tcp.flags.urg',
    'Urgent',
    'Says the urgent pointer field is meaningful. Effectively dead: implementations disagreed about what it pointed at, so nothing relies on it.',
  ),
  flagSpec(
    'tcp.flags.ack',
    'Acknowledgement',
    'Says the acknowledgement number is meaningful. Set on every segment except the very first SYN — which is exactly how a handshake tells its first packet from its second.',
  ),
  flagSpec(
    'tcp.flags.push',
    'Push',
    'Asks the receiver to hand what it has to the application now rather than waiting for more. A hint about buffering, not about the stream itself.',
  ),
  flagSpec(
    'tcp.flags.reset',
    'Reset',
    'Tears the connection down immediately, with no agreement from the other end. It is what a closed port answers with instead of a SYN-ACK.',
  ),
  flagSpec(
    'tcp.flags.syn',
    'Synchronise',
    'Announces an initial sequence number and asks to open a connection. It consumes one sequence number even though it carries no data, which is why the answering acknowledgement is the initial sequence number plus one.',
  ),
  flagSpec(
    'tcp.flags.fin',
    'Finish',
    'Says this side has no more data to send. Each direction is closed separately, so a connection can be half-closed.',
  ),
  {
    id: 'tcp.window_size_value',
    name: 'Window size',
    bits: 16,
    render: (_raw, ctx) => `${ctx.num} bytes`,
    description:
      'How much more data this side is willing to receive right now. It is the whole of TCP’s flow control, and at sixteen bits it stopped being big enough decades ago — hence the window scale option.',
    reference: 'RFC 9293 §3.1',
  },
  {
    id: 'tcp.checksum',
    name: 'Checksum',
    bits: 16,
    render: (_raw, ctx) => hex(ctx.num, 4),
    description:
      'Covers a pseudo-header of the IP addresses and protocol number, then the whole segment. Mandatory here, unlike in UDP: there is no value meaning "not computed".',
    reference: 'RFC 9293 §3.1',
  },
  {
    id: 'tcp.urgent_pointer',
    name: 'Urgent pointer',
    bits: 16,
    render: (_raw, ctx) => String(ctx.num),
    description:
      'Offset of the end of urgent data, and meaningless unless the URG flag is set. Sent as zero by everything that is not trying to be a 1983 Telnet client.',
    reference: 'RFC 9293 §3.1',
  },
]

export const TCP_HEADER_BYTES = specBytes(TCP_SPECS)
/** Data offset with no options: five 32-bit words. */
export const TCP_MIN_DATA_OFFSET = 5

export type TcpOptionInput = { kind: number; value: Uint8Array }

/** Option payload helpers, so an encoder writes values rather than bytes. */
export const optionMss = (bytes: number): Uint8Array =>
  Uint8Array.from([(bytes >> 8) & 0xff, bytes & 0xff])
export const optionWindowScale = (shift: number): Uint8Array => Uint8Array.from([shift & 0xff])

export type TcpInput = {
  srcPort: number
  dstPort: number
  seq: number
  ack: number
  flags: number
  window: number
  options: readonly TcpOptionInput[]
  payload: Uint8Array
  srcIp: string
  dstIp: string
}

/**
 * The addresses are inputs for the same reason as in UDP: the checksum covers
 * them, and they live in the header that will carry this segment.
 *
 * Options are padded to a 32-bit boundary with No-Operation bytes, because the
 * data offset counts whole words and has nowhere to say "and three more bytes".
 */
export function encodeTcp(input: TcpInput): Uint8Array {
  const options = new ByteWriter()
  for (const option of input.options) {
    if (option.kind === TCP_OPTION.NOP || option.kind === TCP_OPTION.END) {
      options.u8(option.kind)
      continue
    }
    options.u8(option.kind).u8(option.value.length + 2).bytes(option.value)
  }
  while (options.length % 4 !== 0) options.u8(TCP_OPTION.NOP)

  const dataOffset = TCP_MIN_DATA_OFFSET + options.length / 4
  const segment = new ByteWriter()
    .u16be(input.srcPort)
    .u16be(input.dstPort)
    .u32be(input.seq >>> 0)
    .u32be(input.ack >>> 0)
    .u16be((dataOffset << 12) | (input.flags & 0x1ff))
    .u16be(input.window)
    .u16be(0) // checksum, stamped below
    .u16be(0) // urgent pointer
    .bytes(options.finish())
    .bytes(input.payload)
    .finish()

  const checksum = tcpChecksum(parseIpv4(input.srcIp), parseIpv4(input.dstIp), segment)
  segment[16] = checksum >> 8
  segment[17] = checksum & 0xff
  return segment
}

export type TcpContext = {
  srcIp?: Uint8Array | undefined
  dstIp?: Uint8Array | undefined
  /** What IPv4 said its payload was. TCP has no length field of its own. */
  length?: number
}

export function decodeTcp(
  frame: Uint8Array,
  offset: number,
  context: TcpContext = {},
): DecodeResult {
  const run = runSpec(TCP_SPECS, frame, offset)
  const children = [...run.nodes]
  const problems = [...run.problems]
  const truncated = run.problems.length > 0

  const available = Math.max(0, frame.length - offset)
  const segmentLength = Math.min(context.length ?? available, available)
  const dataOffset = run.values.get('tcp.hdr_len')
  const srcPort = run.values.get('tcp.srcport')
  const dstPort = run.values.get('tcp.dstport')

  if (!truncated && (dataOffset ?? 0) < TCP_MIN_DATA_OFFSET) {
    const node = children.find((child) => child.id === 'tcp.hdr_len')
    problems.push({
      severity: 'error',
      message: `Data offset is ${dataOffset} words, below the minimum of ${TCP_MIN_DATA_OFFSET}; a header cannot be shorter than its own fixed fields`,
      byteStart: node?.byteStart ?? offset,
      byteLength: node?.byteLength ?? 0,
    })
  }

  // Clamped before anything is read at it, like every untrusted length here.
  const claimedHeader = (dataOffset ?? TCP_MIN_DATA_OFFSET) * 4
  const headerLength = Math.min(
    Math.max(claimedHeader, TCP_HEADER_BYTES),
    Math.max(segmentLength, TCP_HEADER_BYTES),
    available,
  )

  if (!truncated && headerLength > TCP_HEADER_BYTES) {
    const options = decodeOptions(frame, offset + TCP_HEADER_BYTES, offset + headerLength)
    children.push(...options.nodes)
    problems.push(...options.problems)
  }

  if (!truncated) {
    const checksumProblem = verifyChecksum(frame, offset, segmentLength, children, context)
    if (checksumProblem !== undefined) problems.push(checksumProblem)
  }

  const payloadLength = Math.max(0, segmentLength - headerLength)
  if (!truncated && payloadLength > 0) {
    const raw = frame.subarray(offset + headerLength, offset + headerLength + payloadLength)
    children.push({
      id: 'tcp.payload',
      name: 'Payload',
      byteStart: offset + headerLength,
      byteLength: raw.length,
      raw,
      value: formatHexBytes(raw.subarray(0, 16)) + (raw.length > 16 ? ' ...' : ''),
      description:
        'The bytes of the stream this segment carries. TCP itself attaches no meaning to them: where one application message ends and the next begins is not a thing TCP records.',
      reference: 'RFC 9293 §3.1',
    })
  }

  const flags = describeFlags(run.values)
  const seq = run.values.get('tcp.seq') ?? 0
  const summary = truncated
    ? 'TCP (truncated)'
    : `${srcPort} -> ${dstPort} [${flags.join(', ')}] Seq=${seq >>> 0} Win=${run.values.get('tcp.window_size_value') ?? 0} Len=${payloadLength}`

  const node: FieldNode = {
    id: 'tcp',
    name: 'Transmission Control Protocol',
    byteStart: offset,
    byteLength: Math.min(headerLength, available),
    raw: frame.subarray(offset, offset + Math.min(headerLength, available)),
    value: truncated ? 'truncated' : summary,
    description:
      'A reliable, ordered byte stream built on top of a network that offers none of those things. Everything in the header exists to keep two ends agreeing about what has arrived.',
    reference: 'RFC 9293',
    children,
  }

  return { nodes: [node], problems, summary, byteLength: Math.min(headerLength, available) }
}

/** The flags that are set, in the order Wireshark lists them. */
function describeFlags(values: ReadonlyMap<string, number>): string[] {
  const named: [string, string][] = [
    ['tcp.flags.fin', 'FIN'],
    ['tcp.flags.syn', 'SYN'],
    ['tcp.flags.reset', 'RST'],
    ['tcp.flags.push', 'PSH'],
    ['tcp.flags.ack', 'ACK'],
    ['tcp.flags.urg', 'URG'],
  ]
  const set = named.filter(([id]) => values.get(id) === 1).map(([, label]) => label)
  return set.length > 0 ? set : ['no flags']
}

type OptionRun = { nodes: FieldNode[]; problems: Problem[] }

/**
 * The TCP option loop. Same shape as DHCP's and the same rule: every path that
 * continues advances the cursor by at least one byte, so a zero-length option
 * cannot spin.
 *
 * The one structural difference is that the option region has an END, given by
 * the data offset, rather than running to the end of the buffer.
 */
function decodeOptions(frame: Uint8Array, start: number, end: number): OptionRun {
  const nodes: FieldNode[] = []
  const problems: Problem[] = []
  const limit = Math.min(end, frame.length)
  let cursor = start

  while (cursor < limit) {
    const kind = frame[cursor]
    if (kind === undefined) break

    if (kind === TCP_OPTION.END || kind === TCP_OPTION.NOP) {
      nodes.push(simpleOption(frame, cursor, kind))
      cursor += 1
      if (kind === TCP_OPTION.END) break
      continue
    }

    const length = frame[cursor + 1]
    if (length === undefined || cursor + 1 >= limit) {
      problems.push({
        severity: 'error',
        message: `TCP option ${kind} has no length byte: the header ends at ${limit}`,
        byteStart: cursor,
        byteLength: Math.max(0, limit - cursor),
      })
      break
    }
    // A length below two would make no progress, and a length past the option
    // region would read fields belonging to the payload.
    if (length < 2 || cursor + length > limit) {
      problems.push({
        severity: 'error',
        message: `TCP option ${kind} (${optionName(kind)}) declares a length of ${length}, which does not fit the ${limit - cursor} byte(s) of option space left`,
        byteStart: cursor,
        byteLength: Math.max(0, limit - cursor),
      })
      break
    }

    nodes.push(tlvOption(frame, cursor, kind, length))
    cursor += length
  }

  return { nodes, problems }
}

function optionName(kind: number): string {
  return TCP_OPTION_NAMES[kind] ?? 'unknown option'
}

/** END and NOP: one byte, no length, no value. */
function simpleOption(frame: Uint8Array, offset: number, kind: number): FieldNode {
  return {
    id: `tcp.opt.${kind}`,
    name: `Option ${kind}: ${optionName(kind)}`,
    byteStart: offset,
    byteLength: 1,
    raw: frame.subarray(offset, offset + 1),
    value: optionName(kind),
    description:
      kind === TCP_OPTION.NOP
        ? 'A single filler byte. Options have to end on a 32-bit boundary because the data offset counts whole words, and this is how the gap is filled.'
        : 'Marks the end of the option list. Anything after it, up to the data offset, is padding.',
    reference: 'RFC 9293 §3.2',
  }
}

function tlvOption(frame: Uint8Array, offset: number, kind: number, length: number): FieldNode {
  const id = `tcp.opt.${kind}`
  const value = frame.subarray(offset + 2, offset + length)
  const rendered = renderOptionValue(kind, value)

  const children: FieldNode[] = [
    {
      id: `${id}.kind`,
      name: 'Option kind',
      byteStart: offset,
      byteLength: 1,
      raw: frame.subarray(offset, offset + 1),
      value: `${kind} (${optionName(kind)})`,
      description: 'Identifies the option. The registry of kinds is maintained by IANA.',
      reference: 'RFC 9293 §3.2',
    },
    {
      id: `${id}.len`,
      name: 'Length',
      byteStart: offset + 1,
      byteLength: 1,
      raw: frame.subarray(offset + 1, offset + 2),
      value: `${length} bytes (kind and length included)`,
      description:
        'Length of the whole option, not just its value — the opposite convention to DHCP, and a good way to be off by two.',
      reference: 'RFC 9293 §3.2',
    },
  ]

  if (value.length > 0) {
    children.push({
      id: `${id}.value`,
      name: 'Value',
      byteStart: offset + 2,
      byteLength: value.length,
      raw: value,
      value: rendered,
      description: optionDescription(kind),
      reference: 'RFC 9293 §3.2',
    })
  }

  return {
    id,
    name: `Option ${kind}: ${optionName(kind)}`,
    byteStart: offset,
    byteLength: length,
    raw: frame.subarray(offset, offset + length),
    value: rendered,
    description: optionDescription(kind),
    reference: 'RFC 9293 §3.2',
    children,
  }
}

function renderOptionValue(kind: number, value: Uint8Array): string {
  switch (kind) {
    case TCP_OPTION.MSS:
      return `${((value[0] ?? 0) << 8) | (value[1] ?? 0)} bytes`
    case TCP_OPTION.WINDOW_SCALE: {
      const shift = value[0] ?? 0
      return `shift ${shift} (multiply the window by ${2 ** Math.min(shift, 14)})`
    }
    case TCP_OPTION.SACK_PERMITTED:
      return 'permitted'
    default:
      return value.length === 0 ? optionName(kind) : formatHexBytes(value)
  }
}

function optionDescription(kind: number): string {
  switch (kind) {
    case TCP_OPTION.MSS:
      return 'The largest segment this side is willing to receive, not counting headers. Sent only in a SYN, because it describes the connection rather than the segment.'
    case TCP_OPTION.WINDOW_SCALE:
      return 'How far left to shift every window size on this connection, which is how a sixteen-bit field ends up describing a megabyte. Both ends must send it in their SYN or neither side scales.'
    case TCP_OPTION.SACK_PERMITTED:
      return 'Offers selective acknowledgement: the ability to say "I got these ranges" instead of only "I got everything up to here". Negotiated in the handshake, used later.'
    default:
      return 'An option this decoder does not interpret. Its bytes are shown so nothing in the header belongs to nobody.'
  }
}

function verifyChecksum(
  frame: Uint8Array,
  offset: number,
  segmentLength: number,
  children: FieldNode[],
  context: TcpContext,
): Problem | undefined {
  const node = children.find((child) => child.id === 'tcp.checksum')
  if (node === undefined) return undefined

  const stored = ((node.raw[0] ?? 0) << 8) | (node.raw[1] ?? 0)
  const { srcIp, dstIp } = context
  if (srcIp === undefined || dstIp === undefined) {
    node.value = `${hex(stored, 4)} [unverified: no IP header]`
    return undefined
  }

  const expected = tcpChecksum(srcIp, dstIp, frame.subarray(offset, offset + segmentLength))
  if (stored === expected) {
    node.value = `${hex(stored, 4)} [correct]`
    return undefined
  }

  node.value = `${hex(stored, 4)} [incorrect, should be ${hex(expected, 4)}]`
  return {
    severity: 'warning',
    message: `TCP checksum is ${hex(stored, 4)} but the segment and pseudo-header sum to ${hex(expected, 4)}; the receiver would discard it`,
    byteStart: node.byteStart,
    byteLength: node.byteLength,
  }
}

/**
 * Frame builders — the three segments of a connection setup.
 *
 * Protocol facts decided here: that the client's SYN carries no acknowledgement,
 * that a SYN consumes one sequence number so the answer acknowledges ISN + 1,
 * that the server's answer sets both SYN and ACK, that the client's third
 * segment sets only ACK and carries no data, and which options a modern SYN
 * offers. A lesson supplies who connects to whom and the two random numbers each
 * end picks.
 */

export type TcpEndpoint = { mac: string; ip: string }

/**
 * What the client picks for itself: an ephemeral source port and an initial
 * sequence number. Both are random numbers chosen by the host, in the same sense
 * as a DHCP transaction id — which is why a lesson may name them and may not
 * name the well-known port on the other end.
 */
export type TcpClientPick = { ephemeral: number; sequence: number }

/** What the server picks: an initial sequence number of its own. */
export type TcpServerPick = { sequence: number }

/** 1500-byte Ethernet MTU less 40 bytes of IPv4 and TCP header. */
const MSS = 1460
/** Linux's default initial receive windows, unscaled. */
const CLIENT_WINDOW = 64240
const SERVER_WINDOW = 65160
const WINDOW_SCALE_SHIFT = 7
const HANDSHAKE_TTL = 64

/**
 * The options a modern SYN offers, in the order Linux writes them.
 *
 * The two No-Operation bytes in the middle are not filler for its own sake: the
 * data offset counts whole 32-bit words, and this ordering makes the four
 * options add up to exactly twelve bytes. Options are padded rather than the
 * header being allowed to end mid-word.
 */
const SYN_OPTIONS: readonly TcpOptionInput[] = [
  { kind: TCP_OPTION.MSS, value: optionMss(MSS) },
  { kind: TCP_OPTION.NOP, value: new Uint8Array(0) },
  { kind: TCP_OPTION.NOP, value: new Uint8Array(0) },
  { kind: TCP_OPTION.SACK_PERMITTED, value: new Uint8Array(0) },
  { kind: TCP_OPTION.NOP, value: new Uint8Array(0) },
  { kind: TCP_OPTION.WINDOW_SCALE, value: optionWindowScale(WINDOW_SCALE_SHIFT) },
]

type SegmentParts = {
  from: TcpEndpoint
  to: TcpEndpoint
  srcPort: number
  dstPort: number
  seq: number
  ack: number
  flags: number
  window: number
  options: readonly TcpOptionInput[]
  identification: number
}

function segment(parts: SegmentParts): Uint8Array {
  return encodeEthernet({
    dst: parts.to.mac,
    src: parts.from.mac,
    etherType: ETHER_TYPE.IPV4,
    payload: encodeIpv4({
      src: parts.from.ip,
      dst: parts.to.ip,
      protocol: IP_PROTOCOL.TCP,
      ttl: HANDSHAKE_TTL,
      identification: parts.identification,
      payload: encodeTcp({
        srcPort: parts.srcPort,
        dstPort: parts.dstPort,
        seq: parts.seq,
        ack: parts.ack,
        flags: parts.flags,
        window: parts.window,
        options: parts.options,
        payload: new Uint8Array(0),
        srcIp: parts.from.ip,
        dstIp: parts.to.ip,
      }),
    }),
  })
}

/** Client -> server: "I would like a connection, and my stream starts here." */
export function buildTcpSynFrame(
  client: TcpEndpoint,
  server: TcpEndpoint,
  clientPick: TcpClientPick,
): Uint8Array {
  return segment({
    from: client,
    to: server,
    srcPort: clientPick.ephemeral,
    dstPort: TCP_PORT.HTTP,
    seq: clientPick.sequence,
    // Nothing to acknowledge yet: this is the only segment of a connection with
    // the ACK flag clear, which is what makes a SYN scan identifiable.
    ack: 0,
    flags: TCP_FLAG.SYN,
    window: CLIENT_WINDOW,
    options: SYN_OPTIONS,
    identification: 1,
  })
}

/**
 * Server -> client: "accepted, my stream starts here, and I have your first
 * sequence number." The acknowledgement is the client's ISN plus one because a
 * SYN consumes a sequence number even though it carries no data.
 */
export function buildTcpSynAckFrame(
  server: TcpEndpoint,
  client: TcpEndpoint,
  serverPick: TcpServerPick,
  clientPick: TcpClientPick,
): Uint8Array {
  return segment({
    from: server,
    to: client,
    srcPort: TCP_PORT.HTTP,
    dstPort: clientPick.ephemeral,
    seq: serverPick.sequence,
    ack: (clientPick.sequence + 1) >>> 0,
    flags: TCP_FLAG.SYN | TCP_FLAG.ACK,
    window: SERVER_WINDOW,
    options: SYN_OPTIONS,
    identification: 2,
  })
}

/**
 * Client -> server: "and I have yours." Now both ends know both starting points,
 * which is the entire purpose of the exchange — and the reason it takes three
 * messages rather than two.
 */
export function buildTcpAckFrame(
  client: TcpEndpoint,
  server: TcpEndpoint,
  clientPick: TcpClientPick,
  serverPick: TcpServerPick,
): Uint8Array {
  return segment({
    from: client,
    to: server,
    srcPort: clientPick.ephemeral,
    dstPort: TCP_PORT.HTTP,
    seq: (clientPick.sequence + 1) >>> 0,
    ack: (serverPick.sequence + 1) >>> 0,
    flags: TCP_FLAG.ACK,
    window: CLIENT_WINDOW,
    // The connection is established; options belong in the SYN that opened it.
    options: [],
    identification: 3,
  })
}
