/**
 * DNS, RFC 1035 — a query and its answer.
 *
 * The reason DNS is worth implementing is name compression. A name in a DNS
 * message may end with a POINTER to a name earlier in the same message, so a
 * field's value is not a function of its own bytes: `dns.resp.name` is two bytes
 * that mean "whatever is at offset 12". Three consequences run through this file:
 *
 *   - `readName` is the only decoder here that reads outside the field it is
 *     decoding, so it is handed the message bounds explicitly rather than the
 *     frame's.
 *   - A pointer can point at another pointer, and nothing in the format stops it
 *     pointing at itself. That is an unbounded loop written into a wire format,
 *     and clause 2 of the decoder contract is the reason it terminates here: a
 *     visited set, and an iteration budget bounded by the message size.
 *   - It is the one field family whose differential comparison is against our
 *     rendered value rather than against raw bytes, because the bytes genuinely
 *     do not contain the answer.
 */

import { ByteWriter } from '../bytes.ts'
import type { DecodeResult, FieldNode, Problem } from '../field.ts'
import { formatHexBytes, formatIpv4, hex, parseIpv4 } from '../format.ts'
import { enumRender, runSpec, specBytes, type FieldSpec } from '../spec.ts'
import { ETHER_TYPE, encodeEthernet } from './ethernet.ts'
import { IP_PROTOCOL, encodeIpv4 } from './ipv4.ts'
import { encodeUdp } from './udp.ts'

export const DNS_PORT = 53

export const DNS_TYPE = {
  A: 1,
  NS: 2,
  CNAME: 5,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
} as const

export const DNS_TYPE_NAMES: Record<number, string> = {
  [DNS_TYPE.A]: 'A (host address)',
  [DNS_TYPE.NS]: 'NS (name server)',
  [DNS_TYPE.CNAME]: 'CNAME (canonical name)',
  [DNS_TYPE.PTR]: 'PTR (domain pointer)',
  [DNS_TYPE.MX]: 'MX (mail exchange)',
  [DNS_TYPE.TXT]: 'TXT (text)',
  [DNS_TYPE.AAAA]: 'AAAA (IPv6 host address)',
}

export const DNS_CLASS_IN = 1

export const DNS_CLASS_NAMES: Record<number, string> = {
  [DNS_CLASS_IN]: 'IN (Internet)',
  3: 'CH (Chaos)',
  4: 'HS (Hesiod)',
}

const DNS_OPCODE_NAMES: Record<number, string> = {
  0: 'Standard query',
  1: 'Inverse query',
  2: 'Server status request',
  5: 'Update',
}

const DNS_RCODE_NAMES: Record<number, string> = {
  0: 'No error',
  1: 'Format error',
  2: 'Server failure',
  3: 'No such name',
  4: 'Not implemented',
  5: 'Refused',
}

/** A one-bit header flag. */
function flagSpec(id: string, name: string, description: string, dictionary: Record<number, string>): FieldSpec {
  return {
    id,
    name,
    bits: 1,
    render: enumRender(dictionary),
    description,
    reference: 'RFC 1035 §4.1.1',
    values: dictionary,
  }
}

const QUERY_OR_RESPONSE = { 0: 'Query', 1: 'Response' }
const NOT_SET_OR_SET = { 0: 'Not set', 1: 'Set' }

/** The twelve-byte header. Everything after it is variable-length and hand-decoded. */
export const DNS_SPECS: readonly FieldSpec[] = [
  {
    id: 'dns.id',
    name: 'Transaction ID',
    bits: 16,
    render: (_raw, ctx) => hex(ctx.num, 4),
    description:
      'Chosen by the client and copied into the answer, so a resolver can match replies to questions. Over UDP it is also most of what stops an attacker forging an answer — sixteen bits of it, which is why source-port randomisation had to be added on top.',
    reference: 'RFC 1035 §4.1.1',
  },
  flagSpec(
    'dns.flags.response',
    'Response',
    'Whether this message is an answer or a question. The two share a header format exactly so that a resolver can copy, amend and return it.',
    QUERY_OR_RESPONSE,
  ),
  {
    id: 'dns.flags.opcode',
    name: 'Opcode',
    bits: 4,
    render: enumRender(DNS_OPCODE_NAMES),
    description:
      'What kind of query this is. Ordinary lookups are opcode 0; the others are rare enough that many resolvers refuse them outright.',
    reference: 'RFC 1035 §4.1.1',
    values: DNS_OPCODE_NAMES,
  },
  flagSpec(
    'dns.flags.authoritative',
    'Authoritative',
    'Set when the answering server is authoritative for the name — it holds the zone rather than a cached copy of somebody else’s answer.',
    NOT_SET_OR_SET,
  ),
  flagSpec(
    'dns.flags.truncated',
    'Truncated',
    'Set when the answer did not fit the datagram. It is the signal to ask again over TCP, and the whole reason DNS is not a UDP-only protocol.',
    NOT_SET_OR_SET,
  ),
  flagSpec(
    'dns.flags.recdesired',
    'Recursion desired',
    'Asks the server to chase the answer through other servers rather than just returning a referral. A stub resolver on a laptop always sets it.',
    NOT_SET_OR_SET,
  ),
  flagSpec(
    'dns.flags.recavail',
    'Recursion available',
    'The server saying whether it is willing to do that. An authoritative server that is not a resolver leaves it clear.',
    NOT_SET_OR_SET,
  ),
  {
    id: 'dns.flags.z',
    name: 'Reserved',
    bits: 1,
    render: enumRender(NOT_SET_OR_SET),
    description: 'Reserved by RFC 1035 and sent as zero.',
    reference: 'RFC 1035 §4.1.1',
    values: NOT_SET_OR_SET,
  },
  flagSpec(
    'dns.flags.authenticated',
    'Answer authenticated',
    'DNSSEC: the resolver is claiming it verified the signatures on this answer. Retrofitted into one of the reserved bits.',
    NOT_SET_OR_SET,
  ),
  flagSpec(
    'dns.flags.checkdisable',
    'Non-authenticated data acceptable',
    'DNSSEC again: the client saying it will take an answer that failed validation, because it intends to check for itself.',
    NOT_SET_OR_SET,
  ),
  {
    id: 'dns.flags.rcode',
    name: 'Reply code',
    bits: 4,
    render: enumRender(DNS_RCODE_NAMES),
    description:
      'How the query went. "No such name" is a successful DNS transaction reporting that a name does not exist — an answer, not an error.',
    reference: 'RFC 1035 §4.1.1',
    values: DNS_RCODE_NAMES,
  },
  {
    id: 'dns.count.queries',
    name: 'Questions',
    bits: 16,
    render: (_raw, ctx) => String(ctx.num),
    description:
      'How many questions follow. In practice always one: the format allows more, but no resolver implements a partial answer to a multi-question query.',
    reference: 'RFC 1035 §4.1.1',
  },
  {
    id: 'dns.count.answers',
    name: 'Answer records',
    bits: 16,
    render: (_raw, ctx) => String(ctx.num),
    description: 'How many answer records follow the questions.',
    reference: 'RFC 1035 §4.1.1',
  },
  {
    id: 'dns.count.auth_rr',
    name: 'Authority records',
    bits: 16,
    render: (_raw, ctx) => String(ctx.num),
    description:
      'Records naming the servers that are authoritative for the name. A referral is an answer with none of these empty and no answer records at all.',
    reference: 'RFC 1035 §4.1.1',
  },
  {
    id: 'dns.count.add_rr',
    name: 'Additional records',
    bits: 16,
    render: (_raw, ctx) => String(ctx.num),
    description:
      'Records the server volunteers because it expects them to be asked for next — typically the addresses of the servers it just named.',
    reference: 'RFC 1035 §4.1.1',
  },
]

export const DNS_HEADER_BYTES = specBytes(DNS_SPECS)

/** Flag masks within the 16-bit flags word, for the encoder. */
export const DNS_FLAG = {
  RESPONSE: 0x8000,
  AUTHORITATIVE: 0x0400,
  TRUNCATED: 0x0200,
  RECURSION_DESIRED: 0x0100,
  RECURSION_AVAILABLE: 0x0080,
} as const

/** A name on the wire: length-prefixed labels, ended by a zero length. */
export function encodeName(hostname: string): Uint8Array {
  const writer = new ByteWriter()
  for (const label of hostname.split('.')) {
    if (label.length === 0) continue
    if (label.length > 63) {
      throw new RangeError(`encodeName(${JSON.stringify(hostname)}): label ${label} exceeds 63 bytes`)
    }
    writer.u8(label.length)
    for (const character of label) writer.u8(character.charCodeAt(0) & 0xff)
  }
  return writer.u8(0).finish()
}

export type DnsQuestion = { hostname: string; type: number }

export type DnsAnswer = { address: string; ttl: number }

export type DnsMessageInput = {
  id: number
  flags: number
  question: DnsQuestion
  answers: readonly DnsAnswer[]
}

/**
 * The first name in a message starts immediately after the twelve-byte header,
 * so a pointer to the question's name is always 0xC00C. Every real resolver
 * emits exactly this, and it is the compression case a decoder must handle.
 */
const NAME_POINTER_TO_QUESTION = 0xc00c

export function encodeDns(input: DnsMessageInput): Uint8Array {
  const writer = new ByteWriter()
    .u16be(input.id)
    .u16be(input.flags)
    .u16be(1)
    .u16be(input.answers.length)
    .u16be(0) // authority records
    .u16be(0) // additional records
    .bytes(encodeName(input.question.hostname))
    .u16be(input.question.type)
    .u16be(DNS_CLASS_IN)

  for (const answer of input.answers) {
    const address = parseIpv4(answer.address)
    writer
      .u16be(NAME_POINTER_TO_QUESTION)
      .u16be(DNS_TYPE.A)
      .u16be(DNS_CLASS_IN)
      .u32be(answer.ttl)
      .u16be(address.length)
      .bytes(address)
  }
  return writer.finish()
}

export type DnsContext = {
  /** What UDP said its payload was: a DNS message is exactly one datagram. */
  length?: number
}

export function decodeDns(
  frame: Uint8Array,
  offset: number,
  context: DnsContext = {},
): DecodeResult {
  const run = runSpec(DNS_SPECS, frame, offset)
  const children = [...run.nodes]
  const problems = [...run.problems]
  const truncated = run.problems.length > 0

  const available = Math.max(0, frame.length - offset)
  // Everything below is bounded by this, and it is clamped to the frame first.
  const messageEnd = offset + Math.min(context.length ?? available, available)
  const isResponse = run.values.get('dns.flags.response') === 1
  const questionCount = run.values.get('dns.count.queries') ?? 0
  const answerCount = run.values.get('dns.count.answers') ?? 0

  let cursor = offset + DNS_HEADER_BYTES
  let firstName: string | undefined
  let firstAddress: string | undefined

  if (!truncated) {
    const queries = readSection(frame, cursor, messageEnd, offset, questionCount, 'question')
    cursor = queries.end
    problems.push(...queries.problems)
    if (queries.nodes.length > 0) {
      children.push(container('dns.queries', 'Queries', frame, offset + DNS_HEADER_BYTES, cursor, queries.nodes,
        'The questions being asked. A question is a name, a record type and a class — and it is echoed back verbatim in the answer so the client can be sure what was answered.'))
    }
    firstName = queries.firstName

    // If the questions did not parse, the answers do not start where the cursor
    // says they do — the same reason `decodeFrame` stops dispatching after an
    // error rather than reading a payload at a made-up offset.
    const answers = queries.problems.length > 0
      ? { nodes: [], problems: [], end: cursor, firstAddress: undefined }
      : readSection(frame, cursor, messageEnd, offset, answerCount, 'answer')
    problems.push(...answers.problems)
    if (answers.nodes.length > 0) {
      children.push(container('dns.answers', 'Answers', frame, cursor, answers.end, answers.nodes,
        'The records that answer the question. Each carries its own time to live, which is how long a resolver may keep using it without asking again.'))
    }
    firstAddress = answers.firstAddress
    cursor = answers.end
  }

  const what = isResponse ? 'response' : 'query'
  const subject = firstName ?? '?'
  const summary = truncated
    ? 'DNS (truncated)'
    : isResponse
      ? `DNS response ${subject} = ${firstAddress ?? 'no answer'}`
      : `DNS query ${subject}`

  const byteLength = Math.max(0, Math.min(cursor, frame.length) - offset)
  const node: FieldNode = {
    id: 'dns',
    name: 'Domain Name System',
    byteStart: offset,
    byteLength,
    raw: frame.subarray(offset, offset + byteLength),
    value: truncated ? 'truncated' : `${what}: ${subject}`,
    description:
      'Names to addresses. One datagram out, one datagram back, and a message format that repeats names often enough to have invented pointer compression for them in 1987.',
    reference: 'RFC 1035',
    children,
  }

  return { nodes: [node], problems, summary, byteLength }
}

function container(
  id: string,
  name: string,
  frame: Uint8Array,
  start: number,
  end: number,
  children: FieldNode[],
  description: string,
): FieldNode {
  return {
    id,
    name,
    byteStart: start,
    byteLength: Math.max(0, end - start),
    raw: frame.subarray(start, end),
    value: `${children.length} record${children.length === 1 ? '' : 's'}`,
    description,
    reference: 'RFC 1035 §4.1',
    children,
  }
}

type SectionRun = {
  nodes: FieldNode[]
  problems: Problem[]
  end: number
  firstName?: string
  firstAddress?: string
}

/**
 * Read `count` questions or resource records.
 *
 * The count comes off the wire, so it is never trusted as a loop bound on its
 * own: the loop also stops at the end of the message, and every iteration
 * consumes at least one byte.
 */
function readSection(
  frame: Uint8Array,
  start: number,
  messageEnd: number,
  messageStart: number,
  count: number,
  kind: 'question' | 'answer',
): SectionRun {
  const nodes: FieldNode[] = []
  const problems: Problem[] = []
  let cursor = start
  let firstName: string | undefined
  let firstAddress: string | undefined

  for (let index = 0; index < count && cursor < messageEnd; index += 1) {
    const name = readName(frame, cursor, messageStart, messageEnd)
    if (name.problem !== undefined) {
      problems.push(name.problem)
      return { nodes, problems, end: cursor, firstName, firstAddress }
    }
    if (firstName === undefined) firstName = name.name

    const record = kind === 'question'
      ? readQuestion(frame, cursor, messageEnd, name)
      : readResourceRecord(frame, cursor, messageEnd, name)

    if (record === undefined) {
      problems.push({
        severity: 'error',
        message: `DNS ${kind} ${index + 1} runs past the end of the message`,
        byteStart: cursor,
        byteLength: Math.max(0, messageEnd - cursor),
      })
      return { nodes, problems, end: cursor, firstName, firstAddress }
    }

    nodes.push(record.node)
    if (firstAddress === undefined) firstAddress = record.address
    cursor = record.end
  }

  return { nodes, problems, end: cursor, firstName, firstAddress }
}

type RecordRun = { node: FieldNode; end: number; address?: string }

const QUESTION_TAIL_BYTES = 4
const RR_TAIL_BYTES = 10

function readQuestion(
  frame: Uint8Array,
  start: number,
  messageEnd: number,
  name: NameRead,
): RecordRun | undefined {
  const tail = start + name.byteLength
  if (tail + QUESTION_TAIL_BYTES > messageEnd) return undefined

  const type = readU16(frame, tail)
  const children: FieldNode[] = [
    nameNode('dns.qry.name', frame, start, name),
    {
      id: 'dns.qry.type',
      name: 'Type',
      byteStart: tail,
      byteLength: 2,
      raw: frame.subarray(tail, tail + 2),
      value: `${type} (${DNS_TYPE_NAMES[type] ?? 'unknown'})`,
      description:
        'Which kind of record is being asked for. A question for an A record and a question for an AAAA record are two separate queries, which is why a dual-stack host sends both.',
      reference: 'RFC 1035 §4.1.2',
      ...(DNS_TYPE_NAMES[type] !== undefined ? { valueName: DNS_TYPE_NAMES[type] } : {}),
    },
    classNode('dns.qry.class', frame, tail + 2),
  ]

  const end = tail + QUESTION_TAIL_BYTES
  return {
    node: {
      id: 'dns.qry',
      name: `Question: ${name.name}`,
      byteStart: start,
      byteLength: end - start,
      raw: frame.subarray(start, end),
      value: `${name.name}: type ${DNS_TYPE_NAMES[type] ?? type}`,
      description: 'One question: a name, a type and a class.',
      reference: 'RFC 1035 §4.1.2',
      children,
    },
    end,
  }
}

function readResourceRecord(
  frame: Uint8Array,
  start: number,
  messageEnd: number,
  name: NameRead,
): RecordRun | undefined {
  const tail = start + name.byteLength
  if (tail + RR_TAIL_BYTES > messageEnd) return undefined

  const type = readU16(frame, tail)
  const ttl = readU32(frame, tail + 4)
  const rdLength = readU16(frame, tail + 8)
  const dataStart = tail + RR_TAIL_BYTES
  // The record's own length field, clamped to the message before it is used as
  // an offset — the same rule as every other untrusted length here.
  if (dataStart + rdLength > messageEnd) return undefined

  const data = frame.subarray(dataStart, dataStart + rdLength)
  const isAddress = type === DNS_TYPE.A && rdLength === 4
  const address = isAddress ? formatIpv4(data) : undefined

  const children: FieldNode[] = [
    nameNode('dns.resp.name', frame, start, name),
    {
      id: 'dns.resp.type',
      name: 'Type',
      byteStart: tail,
      byteLength: 2,
      raw: frame.subarray(tail, tail + 2),
      value: `${type} (${DNS_TYPE_NAMES[type] ?? 'unknown'})`,
      description: 'Which kind of record this is. It decides how the data at the end is read.',
      reference: 'RFC 1035 §4.1.3',
      ...(DNS_TYPE_NAMES[type] !== undefined ? { valueName: DNS_TYPE_NAMES[type] } : {}),
    },
    classNode('dns.resp.class', frame, tail + 2),
    {
      id: 'dns.resp.ttl',
      name: 'Time to live',
      byteStart: tail + 4,
      byteLength: 4,
      raw: frame.subarray(tail + 4, tail + 8),
      value: `${ttl} seconds`,
      description:
        'How long a resolver may keep this record before asking again. Nothing revokes it early, which is why a short TTL is set days before an address is meant to change.',
      reference: 'RFC 1035 §4.1.3',
    },
    {
      id: 'dns.resp.len',
      name: 'Data length',
      byteStart: tail + 8,
      byteLength: 2,
      raw: frame.subarray(tail + 8, tail + 10),
      value: `${rdLength} bytes`,
      description:
        'Length of the record data that follows, so a resolver can skip a record type it does not understand instead of giving up on the message.',
      reference: 'RFC 1035 §4.1.3',
    },
  ]

  if (rdLength > 0) {
    children.push(
      isAddress
        ? {
            id: 'dns.a',
            name: 'Address',
            byteStart: dataStart,
            byteLength: 4,
            raw: data,
            value: address ?? '',
            description: 'The address the name resolves to. This is the answer the whole exchange existed to fetch.',
            reference: 'RFC 1035 §3.4.1',
          }
        : {
            id: 'dns.rdata',
            name: 'Record data',
            byteStart: dataStart,
            byteLength: data.length,
            raw: data,
            value: formatHexBytes(data.subarray(0, 16)) + (data.length > 16 ? ' ...' : ''),
            description: 'Record data of a type this decoder does not interpret, shown as bytes.',
            reference: 'RFC 1035 §4.1.3',
          },
    )
  }

  const end = dataStart + rdLength
  return {
    node: {
      id: 'dns.resp',
      name: `Answer: ${name.name}`,
      byteStart: start,
      byteLength: end - start,
      raw: frame.subarray(start, end),
      value: address ?? `${DNS_TYPE_NAMES[type] ?? `type ${type}`}, ${rdLength} bytes`,
      description: 'One resource record: a name, a type, a class, a time to live and the data.',
      reference: 'RFC 1035 §4.1.3',
      children,
    },
    end,
    ...(address !== undefined ? { address } : {}),
  }
}

function classNode(id: string, frame: Uint8Array, offset: number): FieldNode {
  const value = readU16(frame, offset)
  return {
    id,
    name: 'Class',
    byteStart: offset,
    byteLength: 2,
    raw: frame.subarray(offset, offset + 2),
    value: `${value} (${DNS_CLASS_NAMES[value] ?? 'unknown'})`,
    description:
      'Which network the record belongs to. It is always IN: the other classes are a 1980s idea of DNS serving more than one internet, and nothing uses them.',
    reference: 'RFC 1035 §3.2.4',
    ...(DNS_CLASS_NAMES[value] !== undefined ? { valueName: DNS_CLASS_NAMES[value] } : {}),
  }
}

/**
 * The name field. Its bytes are either the labels themselves or a pointer to
 * labels elsewhere — so this is the one node in the project whose `value` is not
 * derivable from its own `raw`.
 */
function nameNode(id: string, frame: Uint8Array, offset: number, name: NameRead): FieldNode {
  return {
    id,
    name: name.compressed ? 'Name (compressed)' : 'Name',
    byteStart: offset,
    byteLength: name.byteLength,
    raw: frame.subarray(offset, offset + name.byteLength),
    value: name.name,
    description: name.compressed
      ? 'A pointer to a name earlier in this message. The two high bits of a length byte are set to mark it, which is why a label may not be longer than 63 bytes: the other two values of that pair of bits were reserved for this in advance.'
      : 'A sequence of length-prefixed labels ending with a zero. There are no dots on the wire — the dots in a domain name are the label boundaries.',
    reference: 'RFC 1035 §4.1.2',
  }
}

type NameRead = {
  name: string
  /** Bytes consumed at the field's own position, which is 2 for a pure pointer. */
  byteLength: number
  compressed: boolean
  problem?: Problem
}

/** RFC 1035 §4.1.4: the two high bits of a length byte mark a pointer. */
const POINTER_MASK = 0xc0
const MAX_NAME_BYTES = 255

/**
 * Read a possibly-compressed name.
 *
 * Termination, spelled out because the format does not guarantee it: a label
 * always moves the cursor forward, and a pointer may only jump to an offset not
 * already visited. Both are bounded by the size of the message, and an explicit
 * iteration budget of the same size makes that a fact rather than an argument.
 */
function readName(
  frame: Uint8Array,
  start: number,
  messageStart: number,
  messageEnd: number,
): NameRead {
  const labels: string[] = []
  const visited = new Set<number>([start])
  const budget = Math.max(1, messageEnd - messageStart)
  let cursor = start
  let consumed = 0
  let jumped = false
  let compressed = false

  const fail = (message: string, at: number): NameRead => ({
    name: labels.join('.'),
    byteLength: Math.max(consumed, 1),
    compressed,
    problem: {
      severity: 'error',
      message,
      byteStart: Math.min(at, frame.length),
      byteLength: Math.min(2, Math.max(0, frame.length - at)),
    },
  })

  for (let step = 0; step < budget; step += 1) {
    if (cursor >= messageEnd) return fail(`DNS name at ${start} runs past the end of the message`, cursor)
    const length = frame[cursor]
    if (length === undefined) return fail(`DNS name at ${start} runs past the end of the frame`, cursor)

    if ((length & POINTER_MASK) === POINTER_MASK) {
      const low = frame[cursor + 1]
      if (low === undefined || cursor + 1 >= messageEnd) {
        return fail(`DNS name pointer at ${cursor} is missing its second byte`, cursor)
      }
      const target = messageStart + (((length & 0x3f) << 8) | low)
      if (!jumped) consumed += 2
      jumped = true
      compressed = true

      if (target < messageStart || target >= messageEnd) {
        return fail(`DNS name pointer at ${cursor} points outside the message`, cursor)
      }
      if (visited.has(target)) {
        return fail(`DNS name pointer at ${cursor} points back to ${target}, which this name has already visited`, cursor)
      }
      visited.add(target)
      cursor = target
      continue
    }

    if ((length & POINTER_MASK) !== 0) {
      return fail(`DNS label at ${cursor} uses reserved length bits ${hex(length, 2)}`, cursor)
    }

    if (!jumped) consumed += 1 + length
    if (length === 0) {
      return { name: labels.join('.'), byteLength: Math.max(consumed, 1), compressed }
    }

    const end = cursor + 1 + length
    if (end > messageEnd) {
      return fail(`DNS label at ${cursor} claims ${length} bytes but the message ends at ${messageEnd}`, cursor)
    }
    labels.push(ascii(frame.subarray(cursor + 1, end)))
    if (labels.join('.').length > MAX_NAME_BYTES) {
      return fail(`DNS name at ${start} exceeds the ${MAX_NAME_BYTES}-byte maximum`, cursor)
    }
    cursor = end
  }

  return fail(`DNS name at ${start} did not terminate within the message`, start)
}

function ascii(raw: Uint8Array): string {
  return Array.from(raw, (byte) =>
    byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : '.',
  ).join('')
}

function readU16(frame: Uint8Array, offset: number): number {
  return ((frame[offset] ?? 0) << 8) | (frame[offset + 1] ?? 0)
}

function readU32(frame: Uint8Array, offset: number): number {
  return (
    (frame[offset] ?? 0) * 0x1000000 +
    ((frame[offset + 1] ?? 0) << 16) +
    ((frame[offset + 2] ?? 0) << 8) +
    (frame[offset + 3] ?? 0)
  )
}

/**
 * Frame builders.
 *
 * Protocol facts decided here: that a stub resolver asks for an A record in
 * class IN with recursion desired, that the server answers on the port the query
 * came from, that the answer repeats the question and sets the response and
 * recursion-available flags, and that the answer's name is a compression pointer
 * back to the question's. A lesson supplies who is asking whom, for what name,
 * and how long the answer may be cached.
 */

export type DnsEndpoint = { mac: string; ip: string }

/** What the client picks for itself: an ephemeral source port and a transaction id. */
export type DnsQuery = { ephemeral: number; id: number }

const RESOLVER_TTL = 64

function dnsFrame(
  from: DnsEndpoint,
  to: DnsEndpoint,
  srcPort: number,
  dstPort: number,
  message: Uint8Array,
  identification: number,
): Uint8Array {
  return encodeEthernet({
    dst: to.mac,
    src: from.mac,
    etherType: ETHER_TYPE.IPV4,
    payload: encodeIpv4({
      src: from.ip,
      dst: to.ip,
      protocol: IP_PROTOCOL.UDP,
      ttl: RESOLVER_TTL,
      identification,
      payload: encodeUdp({
        srcPort,
        dstPort,
        srcIp: from.ip,
        dstIp: to.ip,
        payload: message,
      }),
    }),
  })
}

/** Client -> resolver: "what address does this name have?" */
export function buildDnsQueryFrame(
  client: DnsEndpoint,
  resolver: DnsEndpoint,
  query: DnsQuery,
  hostname: string,
): Uint8Array {
  return dnsFrame(
    client,
    resolver,
    query.ephemeral,
    DNS_PORT,
    encodeDns({
      id: query.id,
      flags: DNS_FLAG.RECURSION_DESIRED,
      question: { hostname, type: DNS_TYPE.A },
      answers: [],
    }),
    1,
  )
}

/** Resolver -> client: the same question, plus an answer to it. */
export function buildDnsResponseFrame(
  resolver: DnsEndpoint,
  client: DnsEndpoint,
  query: DnsQuery,
  hostname: string,
  answer: DnsAnswer,
): Uint8Array {
  return dnsFrame(
    resolver,
    client,
    DNS_PORT,
    query.ephemeral,
    encodeDns({
      id: query.id,
      flags: DNS_FLAG.RESPONSE | DNS_FLAG.RECURSION_DESIRED | DNS_FLAG.RECURSION_AVAILABLE,
      question: { hostname, type: DNS_TYPE.A },
      answers: [answer],
    }),
    2,
  )
}
