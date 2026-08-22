/**
 * The differential test: Wireshark is the oracle.
 *
 * We export a .pcap, hand it to tshark, and assert two things — that tshark
 * finds nothing malformed, and that for every leaf field our decoder emits,
 * tshark read the same value out of the same bytes.
 *
 * Comparison is done against `node.raw` (the bytes), not against our rendered
 * display string, so the test measures agreement about the wire format rather
 * than agreement about formatting.
 *
 * The mapping table is written out explicitly even though every Phase 1 field id
 * happens to match tshark's name. DHCP will not be so lucky (our `dhcp.opt.53`
 * vs tshark's `dhcp.option.dhcp`), and an explicit table means a rename on
 * either side fails loudly instead of silently skipping a field.
 */

import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { readBits } from '../src/core/bytes.ts'
import { leafFields, type FieldNode } from '../src/core/field.ts'
import { formatIpv4, formatMac } from '../src/core/format.ts'
import { writePcap } from '../src/core/pcap/write.ts'
import { decodeFrame } from '../src/core/registry.ts'
import { arpSpoofingScenario } from '../src/lessons/arp-spoofing/scenario.ts'
import type { PcapPacket } from '../src/core/pcap/write.ts'
import { arpExchange, arpRequestFrame, dhcpExchange, lessonCapture } from './fixtures.ts'

type Kind = 'mac' | 'ipv4' | 'number' | 'bytes' | 'ascii'

type Mapping = {
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
}

const FIELD_MAP: readonly Mapping[] = [
  { ours: 'eth.dst', theirs: 'eth.dst', kind: 'mac' },
  { ours: 'eth.src', theirs: 'eth.src', kind: 'mac' },
  { ours: 'eth.type', theirs: 'eth.type', kind: 'number' },
  { ours: 'eth.padding', theirs: 'eth.padding', kind: 'bytes' },

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
]

/**
 * Option VALUES, keyed by option code. tshark gives each registered option its
 * own field name — this is the divergence the plan predicted, and the reason the
 * mapping table is written out rather than assumed to be identity.
 *
 * Read with `-E occurrence=a` rather than from the JSON, because an option list
 * repeats field names and JSON objects cannot.
 */
type OptionMapping = { code: number; theirs: string; kind: 'number' | 'ipv4' | 'number-list' }

const OPTION_MAP: readonly OptionMapping[] = [
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
const OPTION_STRUCTURE = /^dhcp\.opt\.\d+(\.(code|len))?$/

function colonHex(raw: Uint8Array): string {
  return Array.from(raw, (b) => b.toString(16).padStart(2, '0')).join(':')
}

/** Canonical form of OUR value, derived from the raw bytes. */
function ourValue(node: FieldNode, frame: Uint8Array, mapping: Mapping): string {
  switch (mapping.kind) {
    case 'mac':
      return formatMac(node.raw)
    case 'ipv4':
      return formatIpv4(node.raw)
    case 'bytes':
      return colonHex(node.raw)
    case 'ascii':
      return asciiValue(node.raw)
    case 'number': {
      const bitPos = mapping.containingByte === true ? node.byteStart * 8 : node.byteStart * 8 + (node.bitOffset ?? 0)
      const bits = mapping.containingByte === true ? node.byteLength * 8 : node.bitLength ?? node.byteLength * 8
      return String(readBits(frame, bitPos, bits) * (mapping.scale ?? 1))
    }
  }
}

/** tshark prints a NUL-terminated string field as its text, and an empty one as nothing. */
function asciiValue(raw: Uint8Array): string {
  const end = raw.indexOf(0)
  return Array.from(raw.subarray(0, end < 0 ? raw.length : end), (b) => String.fromCharCode(b)).join('')
}

/** Canonical form of TSHARK's value. */
function theirValue(text: string, kind: Kind): string {
  switch (kind) {
    case 'mac':
    case 'bytes':
      return text.toLowerCase()
    case 'ascii':
    case 'ipv4':
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
function flattenLayers(layers: Record<string, unknown>): Map<string, string> {
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

function tsharkAvailable(): boolean {
  try {
    execFileSync('tshark', ['-v'], { stdio: 'ignore' })
    return true
  } catch {
    return false
  }
}

const available = tsharkAvailable()
const required = process.env.REQUIRE_TSHARK === '1'

if (!available && !required) {
  // Written straight to stderr rather than via console.warn: vitest intercepts
  // console output and would swallow a module-scope warning, and a silently
  // skipped correctness check is exactly the failure mode this guard exists for.
  process.stderr.write(
    '\n  \u26a0  tshark not found on PATH \u2014 SKIPPING the Wireshark differential test,\n' +
      '     which is this project\'s primary correctness check. Install it with\n' +
      '     `sudo apt install tshark`. CI sets REQUIRE_TSHARK=1, which turns its\n' +
      '     absence into a failure instead of a skip.\n\n',
  )
}

describe('Wireshark differential', () => {
  it('has tshark available when REQUIRE_TSHARK=1', () => {
    if (required) {
      expect(available, 'REQUIRE_TSHARK=1 but tshark is not on PATH').toBe(true)
    }
  })

  it.skipIf(!available)('records the tshark version, so a field rename is traceable in CI logs', () => {
    const version = execFileSync('tshark', ['-v'], { encoding: 'utf8' }).split('\n')[0]
    process.stdout.write(`  oracle: ${version}\n`)
    expect(version).toContain('TShark')
  })

  differential('on generated ARP traffic', 'arp.pcap', arpExchange(), [], 'eth:ethertype:arp')

  // The spoofing lesson makes a claim in prose — that a poisoned cache comes
  // from a packet Wireshark finds nothing wrong with. That claim is only worth
  // making if the oracle backs it, so the whole capture runs through the same
  // differential rather than being taken on trust.
  differential(
    'on the spoofing lesson capture',
    'arp-spoofing.pcap',
    lessonCapture(arpSpoofingScenario),
    // Wireshark's ARP dissector keeps its own mapping across the capture, so it
    // catches the spoof the same way a monitoring tool would — not by finding a
    // malformed frame (there isn't one) but by noticing that 10.0.0.2 changed
    // hardware address. Pinned here because the lesson's prose makes exactly
    // this claim, and prose is not evidence.
    ['4\tDuplicate IP address configured (10.0.0.2)'],
    'eth:ethertype:arp',
  )

  // The whole Phase 4 stack at once: Ethernet, IPv4, UDP and DHCP, including
  // both checksums and an option list read as a sequence.
  differential('on a generated DORA exchange', 'dhcp.pcap', dhcpExchange(), [], 'eth:ethertype:ip:udp:dhcp')

  /**
   * Phase 3.5 makes layer 4 writable, so the oracle should also be asked about
   * bytes a visitor typed rather than only about bytes we encoded. The hardware
   * address length is the one ARP field the rest of the parse depends on: lie
   * about it and tshark sizes its fields from the lie, runs off the end of the
   * frame and reports a malformed packet at error severity. Our decoder must
   * not shrug at a frame Wireshark refuses to dissect.
   */
  it.skipIf(!available)('agrees that a hand-edited hardware-address length is malformed', () => {
    const edited = Uint8Array.from(arpRequestFrame())
    const hwSizeOffset = 18 // Ethernet header (14) + htype (2) + ptype (2)
    edited[hwSizeOffset] = 0xff

    const dir = mkdtempSync(join(tmpdir(), 'packetviz-edit-'))
    const file = join(dir, 'edited.pcap')
    writeFileSync(file, writePcap([{ frame: edited, tMs: 0 }]))

    const expert = execFileSync(
      'tshark',
      ['-r', file, '-T', 'fields', '-e', '_ws.expert.message', '-e', '_ws.expert.severity'],
      { encoding: 'utf8' },
    ).trim()
    rmSync(dir, { recursive: true, force: true })

    expect(expert).toContain('Malformed Packet')
    expect(Number.parseInt(expert.split('\t')[1] ?? '0', 10)).toBeGreaterThanOrEqual(0x800000)

    const ours = decodeFrame(edited).problems
    expect(ours).toHaveLength(1)
    expect(ours[0]?.severity).toBe('error')
    expect(ours[0]?.byteStart).toBe(hwSizeOffset)
  })
})

function differential(
  label: string,
  filename: string,
  packets: PcapPacket[],
  /** Expected `frame.number\tmessage` rows, in order. Usually empty. */
  expectedExpert: readonly string[],
  /** What `frame.protocols` must say for every packet. */
  protocols: string,
) {
  describe.skipIf(!available)(label, () => {
    const dir = available ? mkdtempSync(join(tmpdir(), 'packetviz-')) : ''
    const file = join(dir, filename)

    if (available) writeFileSync(file, writePcap(packets))

    afterAll(() => {
      if (dir) rmSync(dir, { recursive: true, force: true })
    })

    // Wireshark ships with IPv4 and UDP checksum validation OFF by default, so
    // asking it to check them is the only way this test can hold us to them.
    const tshark = (args: string[]): string =>
      execFileSync(
        'tshark',
        ['-r', file, '-o', 'ip.check_checksum:TRUE', '-o', 'udp.check_checksum:TRUE', ...args],
        { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 },
      )

    /** All occurrences of a field, per packet — the only way to read a repeated one. */
    const occurrences = (name: string): string[][] =>
      tshark(['-T', 'fields', '-e', name, '-E', 'occurrence=a'])
        .split('\n')
        .slice(0, packets.length)
        .map((line) => (line.length === 0 ? [] : line.split(',')))

    it('opens the file and finds the expected packet count', () => {
      const parsed: unknown = JSON.parse(tshark(['-T', 'json']))
      expect(Array.isArray(parsed)).toBe(true)
      expect((parsed as unknown[]).length).toBe(packets.length)
    })

    // Assertion A — structural validity. PI_ERROR is 0x800000; anything at or
    // above it means tshark could not dissect what we wrote.
    it('is structurally valid: no expert info reaches error severity', () => {
      const severities = tshark(['-T', 'fields', '-e', '_ws.expert.severity'])
        .split('\n')
        .map((line) => line.trim())
        .filter((line) => line.length > 0)
      for (const severity of severities) {
        expect(Number.parseInt(severity, 10), `expert severity ${severity}`).toBeLessThan(0x800000)
      }
    })

    it('raises exactly the expert info we expect, and nothing else', () => {
      const rows = tshark(['-T', 'fields', '-e', 'frame.number', '-e', '_ws.expert.message'])
        .split('\n')
        .filter((line) => (line.split('\t')[1] ?? '').length > 0)
      expect(rows, 'tshark expert info changed').toEqual([...expectedExpert])
    })

    it(`dissects every packet as ${protocols}`, () => {
      const dissected = tshark(['-T', 'fields', '-e', 'frame.protocols'])
        .split('\n')
        .filter((line) => line.length > 0)
      expect(dissected).toEqual(packets.map(() => protocols))
    })

    /**
     * Every checksum this project computes, recomputed by Wireshark. Status 1 is
     * Good; 2 means "not checked", which is what the default preferences would
     * have given us and is therefore also a failure here.
     */
    it('has every checksum verified as good by Wireshark itself', () => {
      for (const name of ['ip.checksum.status', 'udp.checksum.status']) {
        for (const statuses of occurrences(name)) {
          for (const status of statuses) {
            expect(status, `${name} on a packet in ${filename}`).toBe('1')
          }
        }
      }
    })

    // Assertion B — field equality, for every leaf field we emit.
    it('agrees with our decoder on every mapped field of every packet', () => {
      const json = JSON.parse(tshark(['-T', 'json'])) as {
        _source: { layers: Record<string, unknown> }
      }[]

      let comparisons = 0
      packets.forEach((packet, index) => {
        const theirs = flattenLayers(json[index]?._source.layers ?? {})
        const decoded = decodeFrame(packet.frame)
        expect(decoded.problems).toEqual([])

        const leaves = new Map(Array.from(leafFields(decoded.tree)).map((n) => [n.id, n]))
        for (const mapping of FIELD_MAP) {
          // A capture only carries some of the protocols in the table; the
          // coverage test below is what makes sure nothing we DO emit is skipped.
          const node = leaves.get(mapping.ours)
          if (node === undefined) continue

          const raw = theirs.get(mapping.theirs)
          expect(raw, `packet ${index}: tshark emitted no ${mapping.theirs}`).toBeDefined()

          expect(
            ourValue(node as FieldNode, packet.frame, mapping),
            `packet ${index}, field ${mapping.ours} vs tshark ${mapping.theirs}`,
          ).toBe(theirValue(raw as string, mapping.kind))
          comparisons += 1
        }
      })

      process.stdout.write(`  compared ${comparisons} field values across ${packets.length} packets against tshark\n`)
      expect(comparisons).toBeGreaterThanOrEqual(packets.length * 4)
    })

    // Coverage — a new field cannot silently escape verification.
    it('maps every leaf field our decoder emits', () => {
      const mapped = new Set(FIELD_MAP.map((m) => m.ours))
      const emitted = new Set<string>()
      for (const packet of packets) {
        for (const node of leafFields(decodeFrame(packet.frame).tree)) emitted.add(node.id)
      }

      const unmapped = Array.from(emitted).filter(
        (id) => !mapped.has(id) && !OPTION_STRUCTURE.test(id) && !isMappedOptionValue(id),
      )
      expect(
        unmapped,
        `these fields are decoded but never checked against Wireshark: ${unmapped.join(', ')}`,
      ).toEqual([])
    })

    /**
     * The option list, compared as a list. tshark repeats `dhcp.option.type` and
     * `dhcp.option.length` once per option, so the comparison is between two
     * sequences — which also proves we read the options in the same ORDER, not
     * merely that we found the same ones.
     */
    it('agrees with tshark on the DHCP option list', () => {
      const types = occurrences('dhcp.option.type')
      const lengths = occurrences('dhcp.option.length')
      const ends = occurrences('dhcp.option.end')

      let compared = 0
      packets.forEach((packet, index) => {
        const options = optionNodes(decodeFrame(packet.frame))
        if (options.length === 0) return

        const tlv = options.filter((node) => node.children !== undefined)
        // tshark's field extraction reports the End option's `dhcp.option.type`
        // as 0, even though its own detail tree prints "Option: (255) End". The
        // terminator is therefore checked through `dhcp.option.end` instead, and
        // dropped from the code sequence — pinned here so a future Wireshark
        // that fixes the quirk fails this test loudly instead of drifting.
        expect(tlv.map((node) => optionCode(node.id)).join(','), `packet ${index} option codes`).toBe(
          (types[index] ?? []).slice(0, -1).join(','),
        )
        expect(
          tlv.map((node) => node.byteLength - 2).join(','),
          `packet ${index} option lengths`,
        ).toBe((lengths[index] ?? []).join(','))

        expect(optionCode(options[options.length - 1]?.id ?? ''), `packet ${index} terminator`).toBe(255)
        expect(ends[index], `packet ${index} End option`).toEqual(['255'])
        compared += options.length
      })

      if (compared > 0) process.stdout.write(`  compared ${compared} DHCP options against tshark\n`)
    })

    it('agrees with tshark on every option value it registers a name for', () => {
      const theirs = new Map(OPTION_MAP.map((mapping) => [mapping.code, occurrences(mapping.theirs)]))

      packets.forEach((packet, index) => {
        for (const node of optionNodes(decodeFrame(packet.frame))) {
          const code = optionCode(node.id)
          const mapping = OPTION_MAP.find((candidate) => candidate.code === code)
          const value = node.children?.find((child) => child.id.endsWith('.value'))
          if (mapping === undefined || value === undefined) continue

          expect(
            ourOptionValue(value.raw, mapping.kind),
            `packet ${index}, option ${code} vs tshark ${mapping.theirs}`,
          ).toEqual(theirs.get(code)?.[index] ?? [])
        }
      })
    })

    it('maps no field tshark does not produce', () => {
      const json = JSON.parse(tshark(['-T', 'json'])) as {
        _source: { layers: Record<string, unknown> }
      }[]
      const theirs = new Set<string>()
      for (const packet of json) {
        for (const name of flattenLayers(packet._source.layers).keys()) theirs.add(name)
      }

      // Only fields this capture actually contains: a mapping for ARP is not
      // stale merely because the DHCP capture has no ARP in it.
      const ours = new Set<string>()
      for (const packet of packets) {
        for (const node of leafFields(decodeFrame(packet.frame).tree)) ours.add(node.id)
      }
      const stale = FIELD_MAP.filter((m) => ours.has(m.ours) && !theirs.has(m.theirs)).map(
        (m) => m.theirs,
      )
      expect(stale, `mapping table names fields this tshark does not emit: ${stale.join(', ')}`).toEqual([])
    })
  })
}

/** The option container nodes of a decode, in wire order. */
function optionNodes(packet: { tree: FieldNode[] }): FieldNode[] {
  const dhcp = packet.tree.find((node) => node.id === 'dhcp')
  return (dhcp?.children ?? []).filter((node) => OPTION_STRUCTURE.test(node.id))
}

function optionCode(id: string): number {
  return Number.parseInt(id.slice('dhcp.opt.'.length), 10)
}

function isMappedOptionValue(id: string): boolean {
  const match = /^dhcp\.opt\.(\d+)\.value$/.exec(id)
  return match !== null && OPTION_MAP.some((mapping) => mapping.code === Number(match[1]))
}

/** Our option value in tshark's shape: one string per occurrence tshark reports. */
function ourOptionValue(raw: Uint8Array, kind: OptionMapping['kind']): string[] {
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
