/**
 * Address Resolution Protocol over Ethernet/IPv4 — a fixed 28-byte payload.
 *
 * Field ids match tshark's (`arp.hw.type`, `arp.opcode`, `arp.src.hw_mac`, ...)
 * for the Phase 2 differential test.
 */

import { ByteWriter } from '../bytes.ts'
import type { DecodeResult, FieldNode } from '../field.ts'
import { formatIpv4, formatMac, hex, parseIpv4, parseMac } from '../format.ts'
import { enumRender, runSpec, specBytes, type FieldSpec } from '../spec.ts'
import { ETHER_TYPE, ETHER_TYPE_NAMES } from './ethernet.ts'

export const ARP_HW_TYPE_ETHERNET = 1
export const ARP_HW_SIZE_ETHERNET = 6
export const ARP_PROTO_SIZE_IPV4 = 4

export const ARP_OPCODE = {
  REQUEST: 1,
  REPLY: 2,
} as const

export const ARP_OPCODE_NAMES: Record<number, string> = {
  [ARP_OPCODE.REQUEST]: 'Request',
  [ARP_OPCODE.REPLY]: 'Reply',
}

const ARP_HW_TYPE_NAMES: Record<number, string> = {
  [ARP_HW_TYPE_ETHERNET]: 'Ethernet',
}

export const ARP_SPECS: readonly FieldSpec[] = [
  {
    id: 'arp.hw.type',
    name: 'Hardware type',
    bits: 16,
    render: enumRender(ARP_HW_TYPE_NAMES),
    description:
      'The kind of link-layer address being resolved. 1 is Ethernet. ARP was designed to be link-layer agnostic, and this field is what makes that work.',
    reference: 'RFC 826 §2',
    values: ARP_HW_TYPE_NAMES,
  },
  {
    id: 'arp.proto.type',
    name: 'Protocol type',
    bits: 16,
    render: enumRender(ETHER_TYPE_NAMES, (value) => hex(value, 4)),
    description:
      'The kind of protocol address being resolved, using the EtherType number space. 0x0800 is IPv4.',
    reference: 'RFC 826 §2',
    values: ETHER_TYPE_NAMES,
  },
  {
    id: 'arp.hw.size',
    name: 'Hardware address length',
    bits: 8,
    render: (_raw, ctx) => `${ctx.num} bytes`,
    description: 'Length of each hardware address in bytes. 6 for an Ethernet MAC address.',
    reference: 'RFC 826 §2',
  },
  {
    id: 'arp.proto.size',
    name: 'Protocol address length',
    bits: 8,
    render: (_raw, ctx) => `${ctx.num} bytes`,
    description: 'Length of each protocol address in bytes. 4 for an IPv4 address.',
    reference: 'RFC 826 §2',
  },
  {
    id: 'arp.opcode',
    name: 'Opcode',
    bits: 16,
    render: enumRender(ARP_OPCODE_NAMES),
    description:
      'What this packet is doing. 1 is a request ("who has this IP address?"), 2 is a reply ("I do, and here is my MAC"). Request and reply carry the identical 28-byte layout — only this field distinguishes them.',
    reference: 'RFC 826 §2',
    values: ARP_OPCODE_NAMES,
  },
  {
    id: 'arp.src.hw_mac',
    name: 'Sender MAC address',
    bits: 48,
    render: (raw) => formatMac(raw),
    description:
      'Hardware address of the host that built this packet. Receivers cache the sender MAC/IP pair from any ARP packet they see, which is exactly why ARP can be spoofed.',
    reference: 'RFC 826 §2',
  },
  {
    id: 'arp.src.proto_ipv4',
    name: 'Sender IP address',
    bits: 32,
    render: (raw) => formatIpv4(raw),
    description: 'The IPv4 address the sender claims to own.',
    reference: 'RFC 826 §2',
  },
  {
    id: 'arp.dst.hw_mac',
    name: 'Target MAC address',
    bits: 48,
    render: (raw) => formatMac(raw),
    description:
      'Hardware address of the target. All zeros in a request, because it is precisely the unknown being asked about.',
    reference: 'RFC 826 §2',
  },
  {
    id: 'arp.dst.proto_ipv4',
    name: 'Target IP address',
    bits: 32,
    render: (raw) => formatIpv4(raw),
    description: 'The IPv4 address being resolved.',
    reference: 'RFC 826 §2',
  },
]

export const ARP_PAYLOAD_BYTES = specBytes(ARP_SPECS)

export type ArpInput = {
  opcode: number
  senderMac: string
  senderIp: string
  targetMac: string
  targetIp: string
}

export function encodeArp(input: ArpInput): Uint8Array {
  return new ByteWriter()
    .u16be(ARP_HW_TYPE_ETHERNET)
    .u16be(ETHER_TYPE.IPV4)
    .u8(ARP_HW_SIZE_ETHERNET)
    .u8(ARP_PROTO_SIZE_IPV4)
    .u16be(input.opcode)
    .bytes(parseMac(input.senderMac))
    .bytes(parseIpv4(input.senderIp))
    .bytes(parseMac(input.targetMac))
    .bytes(parseIpv4(input.targetIp))
    .finish()
}

export function decodeArp(frame: Uint8Array, offset: number): DecodeResult {
  const run = runSpec(ARP_SPECS, frame, offset)
  const truncated = run.problems.length > 0

  const node: FieldNode = {
    id: 'arp',
    name: 'Address Resolution Protocol',
    byteStart: offset,
    byteLength: run.byteLength,
    raw: frame.subarray(offset, offset + run.byteLength),
    value: truncated ? 'truncated' : summarise(run.nodes),
    description:
      'Maps an IPv4 address to the MAC address that owns it, so a host can address a frame to a neighbour it only knows by IP.',
    reference: 'RFC 826',
    children: run.nodes,
  }

  return {
    nodes: [node],
    problems: run.problems,
    summary: truncated ? 'ARP (truncated)' : summarise(run.nodes),
    byteLength: run.byteLength,
  }
}

function summarise(nodes: readonly FieldNode[]): string {
  const value = (id: string): string => nodes.find((node) => node.id === id)?.value ?? '?'
  const opcode = nodes.find((node) => node.id === 'arp.opcode')
  const senderIp = value('arp.src.proto_ipv4')
  const targetIp = value('arp.dst.proto_ipv4')

  if (opcode?.raw.length === 2) {
    const code = (opcode.raw[0] as number) * 256 + (opcode.raw[1] as number)
    if (code === ARP_OPCODE.REQUEST) return `Who has ${targetIp}? Tell ${senderIp}`
    if (code === ARP_OPCODE.REPLY) return `${senderIp} is at ${value('arp.src.hw_mac')}`
  }
  return `ARP ${senderIp} -> ${targetIp}`
}
