/**
 * The Wireshark oracle, shared by every test that asks it a question.
 *
 * Holds the mapping between our field ids and tshark's names, and the two
 * canonicalisation functions that put both sides in the same shape. Comparison
 * is done against `node.raw` (the bytes), not against our rendered display
 * string, so the tests measure agreement about the wire format rather than
 * agreement about formatting.
 *
 * The mapping table is written out explicitly even though most field ids happen
 * to match tshark's name. DHCP is where that luck runs out (our `dhcp.opt.53`
 * vs tshark's `dhcp.option.dhcp`), and an explicit table means a rename on
 * either side fails loudly instead of silently skipping a field.
 *
 * It lives outside `tshark-diff.test.ts` because `import.test.ts` asks the same
 * questions of a file this project did not write, and one mapping table that
 * both use is the only way those two answers are comparable.
 */

import { execFileSync } from 'node:child_process'
import { readBits } from '../src/core/bytes.ts'
import type { FieldNode } from '../src/core/field.ts'
import { formatIpv4, formatMac } from '../src/core/format.ts'

export type Kind = 'mac' | 'ipv4' | 'number' | 'bytes' | 'ascii' | 'name'

export type Mapping = {
  /** Our field id. */
  ours: string
  /** tshark's field name. */
  theirs: string
  kind: Kind
  /**
   * Set when tshark reports the field in different units from the wire value:
   * `ip.hdr_len` is words on the wire and bytes in tshark, `ip.frag_offset` is
   * eight-byte units on the wire and bytes in tshark. `theirs = ours * scale`.
   */
  scale?: number
  /**
   * Set when tshark models the field as the whole byte(s) it shares with its
   * neighbours rather than as the RFC's bit range. `ip.flags` is the case: the
   * RFC defines three bits, and tshark reports the byte those bits sit in,
   * fragment-offset bits included. Comparing the containing byte is the only
   * thing both models actually agree about.
   */
  containingByte?: true
  /**
   * Set when tshark emits the field for some packets and not others, with the
   * reason. DNS is the case: Wireshark hides the three flag bits that only mean
   * something in a response, so a query has no `dns.flags.authoritative` even
   * though the bit is right there in the byte. We show it, because it is in the
   * buffer and this project's whole claim is that the tree is a decode of the
   * buffer.
   *
   * A mapping marked this way is skipped only for the packets tshark left it out
   * of. If tshark never emits it anywhere in a capture that contains the field,
   * the stale-mapping test still fails — so a typo cannot hide here.
   */
  sometimesAbsent?: string
}

export const FIELD_MAP: readonly Mapping[] = [
  { ours: 'eth.dst', theirs: 'eth.dst', kind: 'mac' },
  { ours: 'eth.src', theirs: 'eth.src', kind: 'mac' },
  { ours: 'eth.type', theirs: 'eth.type', kind: 'number' },
  { ours: 'eth.padding', theirs: 'eth.padding', kind: 'bytes' },
  // Wireshark reserves "padding" for bytes that brought the frame up to the
  // 60-byte minimum and calls everything else a trailer. We follow it, because
  // a foreign capture proved the two are distinguishable.
  { ours: 'eth.trailer', theirs: 'eth.trailer', kind: 'bytes' },

  { ours: 'arp.hw.type', theirs: 'arp.hw.type', kind: 'number' },
  { ours: 'arp.proto.type', theirs: 'arp.proto.type', kind: 'number' },
  { ours: 'arp.hw.size', theirs: 'arp.hw.size', kind: 'number' },
  { ours: 'arp.proto.size', theirs: 'arp.proto.size', kind: 'number' },
  { ours: 'arp.opcode', theirs: 'arp.opcode', kind: 'number' },
  { ours: 'arp.src.hw_mac', theirs: 'arp.src.hw_mac', kind: 'mac' },
  { ours: 'arp.src.proto_ipv4', theirs: 'arp.src.proto_ipv4', kind: 'ipv4' },
  { ours: 'arp.dst.hw_mac', theirs: 'arp.dst.hw_mac', kind: 'mac' },
  { ours: 'arp.dst.proto_ipv4', theirs: 'arp.dst.proto_ipv4', kind: 'ipv4' },

  { ours: 'ip.version', theirs: 'ip.version', kind: 'number' },
  { ours: 'ip.hdr_len', theirs: 'ip.hdr_len', kind: 'number', scale: 4 },
  { ours: 'ip.dsfield.dscp', theirs: 'ip.dsfield.dscp', kind: 'number' },
  { ours: 'ip.dsfield.ecn', theirs: 'ip.dsfield.ecn', kind: 'number' },
  { ours: 'ip.len', theirs: 'ip.len', kind: 'number' },
  { ours: 'ip.id', theirs: 'ip.id', kind: 'number' },
  { ours: 'ip.flags', theirs: 'ip.flags', kind: 'number', containingByte: true },
  { ours: 'ip.frag_offset', theirs: 'ip.frag_offset', kind: 'number', scale: 8 },
  { ours: 'ip.ttl', theirs: 'ip.ttl', kind: 'number' },
  { ours: 'ip.proto', theirs: 'ip.proto', kind: 'number' },
  { ours: 'ip.checksum', theirs: 'ip.checksum', kind: 'number' },
  { ours: 'ip.src', theirs: 'ip.src', kind: 'ipv4' },
  { ours: 'ip.dst', theirs: 'ip.dst', kind: 'ipv4' },

  { ours: 'udp.srcport', theirs: 'udp.srcport', kind: 'number' },
  { ours: 'udp.dstport', theirs: 'udp.dstport', kind: 'number' },
  { ours: 'udp.length', theirs: 'udp.length', kind: 'number' },
  { ours: 'udp.checksum', theirs: 'udp.checksum', kind: 'number' },

  { ours: 'dhcp.type', theirs: 'dhcp.type', kind: 'number' },
  { ours: 'dhcp.hw.type', theirs: 'dhcp.hw.type', kind: 'number' },
  { ours: 'dhcp.hw.len', theirs: 'dhcp.hw.len', kind: 'number' },
  { ours: 'dhcp.hops', theirs: 'dhcp.hops', kind: 'number' },
  { ours: 'dhcp.id', theirs: 'dhcp.id', kind: 'number' },
  { ours: 'dhcp.secs', theirs: 'dhcp.secs', kind: 'number' },
  { ours: 'dhcp.flags', theirs: 'dhcp.flags', kind: 'number' },
  { ours: 'dhcp.ip.client', theirs: 'dhcp.ip.client', kind: 'ipv4' },
  { ours: 'dhcp.ip.your', theirs: 'dhcp.ip.your', kind: 'ipv4' },
  { ours: 'dhcp.ip.server', theirs: 'dhcp.ip.server', kind: 'ipv4' },
  { ours: 'dhcp.ip.relay', theirs: 'dhcp.ip.relay', kind: 'ipv4' },
  { ours: 'dhcp.hw.mac_addr', theirs: 'dhcp.hw.mac_addr', kind: 'mac' },
  { ours: 'dhcp.hw.addr_padding', theirs: 'dhcp.hw.addr_padding', kind: 'bytes' },
  { ours: 'dhcp.server', theirs: 'dhcp.server', kind: 'ascii' },
  { ours: 'dhcp.file', theirs: 'dhcp.file', kind: 'ascii' },
  // tshark renders the four cookie bytes as if they were an address, so
  // 0x63825363 comes back as 99.130.83.99. Same bytes, stranger clothes.
  { ours: 'dhcp.cookie', theirs: 'dhcp.cookie', kind: 'ipv4' },

  { ours: 'icmp.type', theirs: 'icmp.type', kind: 'number' },
  { ours: 'icmp.code', theirs: 'icmp.code', kind: 'number' },
  { ours: 'icmp.checksum', theirs: 'icmp.checksum', kind: 'number' },
  { ours: 'icmp.ident', theirs: 'icmp.ident', kind: 'number' },
  { ours: 'icmp.seq', theirs: 'icmp.seq', kind: 'number' },
  // An echo payload means nothing to ICMP, so Wireshark hands it to the generic
  // data dissector and it arrives as a layer of its own rather than an ICMP field.
  { ours: 'icmp.data', theirs: 'data.data', kind: 'bytes' },

  { ours: 'tcp.srcport', theirs: 'tcp.srcport', kind: 'number' },
  { ours: 'tcp.dstport', theirs: 'tcp.dstport', kind: 'number' },
  // The pinned divergence worth understanding: Wireshark shows sequence and
  // acknowledgement numbers RELATIVE to each side's initial number by default,
  // which is a fact about the capture rather than about the packet. `tcp.seq`
  // is therefore its relative number and `tcp.seq_raw` is the wire value — the
  // one our decoder reports, because the wire value is what is in the buffer.
  { ours: 'tcp.seq', theirs: 'tcp.seq_raw', kind: 'number' },
  { ours: 'tcp.ack', theirs: 'tcp.ack_raw', kind: 'number' },
  { ours: 'tcp.hdr_len', theirs: 'tcp.hdr_len', kind: 'number', scale: 4 },
  { ours: 'tcp.flags.res', theirs: 'tcp.flags.res', kind: 'number' },
  { ours: 'tcp.flags.ns', theirs: 'tcp.flags.ns', kind: 'number' },
  { ours: 'tcp.flags.cwr', theirs: 'tcp.flags.cwr', kind: 'number' },
  { ours: 'tcp.flags.ecn', theirs: 'tcp.flags.ecn', kind: 'number' },
  { ours: 'tcp.flags.urg', theirs: 'tcp.flags.urg', kind: 'number' },
  { ours: 'tcp.flags.ack', theirs: 'tcp.flags.ack', kind: 'number' },
  { ours: 'tcp.flags.push', theirs: 'tcp.flags.push', kind: 'number' },
  { ours: 'tcp.flags.reset', theirs: 'tcp.flags.reset', kind: 'number' },
  { ours: 'tcp.flags.syn', theirs: 'tcp.flags.syn', kind: 'number' },
  { ours: 'tcp.flags.fin', theirs: 'tcp.flags.fin', kind: 'number' },
  { ours: 'tcp.window_size_value', theirs: 'tcp.window_size_value', kind: 'number' },
  { ours: 'tcp.checksum', theirs: 'tcp.checksum', kind: 'number' },
  { ours: 'tcp.urgent_pointer', theirs: 'tcp.urgent_pointer', kind: 'number' },
  // Options: tshark names each one after what it is rather than after its kind
  // byte, so these are the same divergence DHCP has, one layer down.
  { ours: 'tcp.opt.1', theirs: 'tcp.options.nop', kind: 'bytes' },
  { ours: 'tcp.opt.2.value', theirs: 'tcp.options.mss_val', kind: 'number' },
  { ours: 'tcp.opt.3.value', theirs: 'tcp.options.wscale.shift', kind: 'number' },

  { ours: 'dns.id', theirs: 'dns.id', kind: 'number' },
  { ours: 'dns.flags.response', theirs: 'dns.flags.response', kind: 'number' },
  { ours: 'dns.flags.opcode', theirs: 'dns.flags.opcode', kind: 'number' },
  {
    ours: 'dns.flags.authoritative',
    theirs: 'dns.flags.authoritative',
    kind: 'number',
    sometimesAbsent: 'Wireshark hides it in a query: only meaningful in a response',
  },
  { ours: 'dns.flags.truncated', theirs: 'dns.flags.truncated', kind: 'number' },
  { ours: 'dns.flags.recdesired', theirs: 'dns.flags.recdesired', kind: 'number' },
  {
    ours: 'dns.flags.recavail',
    theirs: 'dns.flags.recavail',
    kind: 'number',
    sometimesAbsent: 'Wireshark hides it in a query: only meaningful in a response',
  },
  { ours: 'dns.flags.z', theirs: 'dns.flags.z', kind: 'number' },
  {
    ours: 'dns.flags.authenticated',
    theirs: 'dns.flags.authenticated',
    kind: 'number',
    sometimesAbsent: 'Wireshark hides it in a query: only meaningful in a response',
  },
  { ours: 'dns.flags.checkdisable', theirs: 'dns.flags.checkdisable', kind: 'number' },
  {
    ours: 'dns.flags.rcode',
    theirs: 'dns.flags.rcode',
    kind: 'number',
    sometimesAbsent: 'Wireshark hides it in a query: a question has no reply code',
  },
  { ours: 'dns.count.queries', theirs: 'dns.count.queries', kind: 'number' },
  { ours: 'dns.count.answers', theirs: 'dns.count.answers', kind: 'number' },
  { ours: 'dns.count.auth_rr', theirs: 'dns.count.auth_rr', kind: 'number' },
  { ours: 'dns.count.add_rr', theirs: 'dns.count.add_rr', kind: 'number' },
  // The two `name` fields are the only comparison in this table made against our
  // DECODED value rather than against the field's own bytes — because a
  // compressed name's bytes are a pointer, and the name is somewhere else in the
  // message. Comparing raw here would be comparing two pointers and learning
  // nothing about whether we followed them to the same place.
  { ours: 'dns.qry.name', theirs: 'dns.qry.name', kind: 'name' },
  { ours: 'dns.qry.type', theirs: 'dns.qry.type', kind: 'number' },
  { ours: 'dns.qry.class', theirs: 'dns.qry.class', kind: 'number' },
  { ours: 'dns.resp.name', theirs: 'dns.resp.name', kind: 'name' },
  { ours: 'dns.resp.type', theirs: 'dns.resp.type', kind: 'number' },
  { ours: 'dns.resp.class', theirs: 'dns.resp.class', kind: 'number' },
  { ours: 'dns.resp.ttl', theirs: 'dns.resp.ttl', kind: 'number' },
  { ours: 'dns.resp.len', theirs: 'dns.resp.len', kind: 'number' },
  { ours: 'dns.a', theirs: 'dns.a', kind: 'ipv4' },
]

/**
 * Option VALUES, keyed by option code. tshark gives each registered option its
 * own field name — this is the divergence the plan predicted, and the reason the
 * mapping table is written out rather than assumed to be identity.
 *
 * Read with `-E occurrence=a` rather than from the JSON, because an option list
 * repeats field names and JSON objects cannot.
 */
export type OptionMapping = { code: number; theirs: string; kind: 'number' | 'ipv4' | 'number-list' }

export const OPTION_MAP: readonly OptionMapping[] = [
  { code: 1, theirs: 'dhcp.option.subnet_mask', kind: 'ipv4' },
  { code: 3, theirs: 'dhcp.option.router', kind: 'ipv4' },
  { code: 6, theirs: 'dhcp.option.domain_name_server', kind: 'ipv4' },
  { code: 50, theirs: 'dhcp.option.requested_ip_address', kind: 'ipv4' },
  { code: 51, theirs: 'dhcp.option.ip_address_lease_time', kind: 'number' },
  { code: 53, theirs: 'dhcp.option.dhcp', kind: 'number' },
  { code: 54, theirs: 'dhcp.option.dhcp_server_id', kind: 'ipv4' },
  { code: 55, theirs: 'dhcp.option.request_list_item', kind: 'number-list' },
]

/**
 * The structural parts of an option — the option node itself, its code byte and
 * its length byte — are verified by the option-list test rather than field by
 * field, because tshark models them as repeated `dhcp.option.type` and
 * `dhcp.option.length` occurrences instead of as one field per option.
 */
export const OPTION_STRUCTURE = /^dhcp\.opt\.\d+(\.(code|len))?$/

/**
 * The same arrangement for TCP: tshark reports `tcp.option_kind` and
 * `tcp.option_len` once per option instead of one field per option, so the
 * structural bytes are verified as a SEQUENCE by the option-list test and the
 * values are mapped individually above.
 */
export const TCP_OPTION_STRUCTURE = /^tcp\.opt\.\d+\.(kind|len)$/

export function colonHex(raw: Uint8Array): string {
  return Array.from(raw, (b) => b.toString(16).padStart(2, '0')).join(':')
}

/** Canonical form of OUR value, derived from the raw bytes. */
export function ourValue(node: FieldNode, frame: Uint8Array, mapping: Mapping): string {
  switch (mapping.kind) {
    case 'mac':
      return formatMac(node.raw)
    case 'ipv4':
      return formatIpv4(node.raw)
    case 'bytes':
      return colonHex(node.raw)
    case 'ascii':
      return asciiValue(node.raw)
    case 'name':
      return node.value
    case 'number': {
      const bitPos = mapping.containingByte === true ? node.byteStart * 8 : node.byteStart * 8 + (node.bitOffset ?? 0)
      const bits = mapping.containingByte === true ? node.byteLength * 8 : node.bitLength ?? node.byteLength * 8
      return String(readBits(frame, bitPos, bits) * (mapping.scale ?? 1))
    }
  }
}

/** tshark prints a NUL-terminated string field as its text, and an empty one as nothing. */
export function asciiValue(raw: Uint8Array): string {
  const end = raw.indexOf(0)
  return Array.from(raw.subarray(0, end < 0 ? raw.length : end), (b) => String.fromCharCode(b)).join('')
}

/** Canonical form of TSHARK's value. */
export function theirValue(text: string, kind: Kind): string {
  switch (kind) {
    case 'mac':
    case 'bytes':
      return text.toLowerCase()
    case 'ascii':
    case 'ipv4':
    case 'name':
      return text
    case 'number':
      return String(text.startsWith('0x') ? Number.parseInt(text, 16) : Number.parseInt(text, 10))
  }
}

/**
 * tshark's JSON nests fields under one object per layer, and puts extra derived
 * fields in `*_tree` sub-objects. Flatten the top level of each layer; the
 * sub-objects are not string-valued, so they drop out on their own.
 */
export function flattenLayers(layers: Record<string, unknown>): Map<string, string> {
  const out = new Map<string, string>()

  // Recursive, because tshark nests a field's bit-level children under a
  // `*_tree` sibling: `ip.dsfield.dscp` lives inside `ip.dsfield_tree`, not
  // beside `ip.dsfield`. Top-level entries are visited first and win, so a
  // nested field can never shadow the field it belongs to.
  const visit = (value: unknown): void => {
    if (typeof value !== 'object' || value === null) return
    for (const [name, child] of Object.entries(value as Record<string, unknown>)) {
      if (typeof child === 'string' && !out.has(name)) out.set(name, child)
    }
    for (const child of Object.values(value as Record<string, unknown>)) visit(child)
  }

  visit(layers)
  return out
}

export function tsharkAvailable(): boolean {
  try {
    execFileSync('tshark', ['-v'], { stdio: 'ignore' })
    return true
  } catch {
    return false
  }
}
/** The TCP option nodes of a decode, in wire order — NOPs and ENDs included. */
export function tcpOptionNodes(packet: { tree: FieldNode[] }): FieldNode[] {
  const ip = packet.tree.find((node) => node.id === 'ip')
  const tcp = ip?.children?.find((node) => node.id === 'tcp')
    ?? packet.tree.find((node) => node.id === 'tcp')
  return (tcp?.children ?? []).filter((node) => /^tcp\.opt\.\d+$/.test(node.id))
}

/** The option container nodes of a decode, in wire order. */
export function optionNodes(packet: { tree: FieldNode[] }): FieldNode[] {
  const dhcp = packet.tree.find((node) => node.id === 'dhcp')
  return (dhcp?.children ?? []).filter((node) => OPTION_STRUCTURE.test(node.id))
}

export function optionCode(id: string): number {
  return Number.parseInt(id.slice('dhcp.opt.'.length), 10)
}

export function isMappedOptionValue(id: string): boolean {
  const match = /^dhcp\.opt\.(\d+)\.value$/.exec(id)
  return match !== null && OPTION_MAP.some((mapping) => mapping.code === Number(match[1]))
}

/** Our option value in tshark's shape: one string per occurrence tshark reports. */
export function ourOptionValue(raw: Uint8Array, kind: OptionMapping['kind']): string[] {
  switch (kind) {
    case 'ipv4': {
      const addresses: string[] = []
      for (let i = 0; i + 4 <= raw.length; i += 4) addresses.push(formatIpv4(raw.subarray(i, i + 4)))
      return addresses
    }
    case 'number-list':
      return Array.from(raw, (byte) => String(byte))
    case 'number':
      return [String(raw.reduce((sum, byte) => sum * 256 + byte, 0))]
  }
}

