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
import { arpExchange, arpRequestFrame, lessonCapture } from './fixtures.ts'

type Kind = 'mac' | 'ipv4' | 'number' | 'bytes'

type Mapping = {
  /** Our field id. */
  ours: string
  /** tshark's field name. */
  theirs: string
  kind: Kind
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
]

function colonHex(raw: Uint8Array): string {
  return Array.from(raw, (b) => b.toString(16).padStart(2, '0')).join(':')
}

/** Canonical form of OUR value, derived from the raw bytes. */
function ourValue(node: FieldNode, frame: Uint8Array, kind: Kind): string {
  switch (kind) {
    case 'mac':
      return formatMac(node.raw)
    case 'ipv4':
      return formatIpv4(node.raw)
    case 'bytes':
      return colonHex(node.raw)
    case 'number': {
      const bitPos = node.byteStart * 8 + (node.bitOffset ?? 0)
      return String(readBits(frame, bitPos, node.bitLength ?? node.byteLength * 8))
    }
  }
}

/** Canonical form of TSHARK's value. */
function theirValue(text: string, kind: Kind): string {
  switch (kind) {
    case 'mac':
    case 'bytes':
      return text.toLowerCase()
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
  for (const layer of Object.values(layers)) {
    if (typeof layer !== 'object' || layer === null) continue
    for (const [name, value] of Object.entries(layer as Record<string, unknown>)) {
      if (typeof value === 'string' && !out.has(name)) out.set(name, value)
    }
  }
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

  differential('on generated ARP traffic', 'arp.pcap', arpExchange(), [])

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
  )

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
) {
  describe.skipIf(!available)(label, () => {
    const dir = available ? mkdtempSync(join(tmpdir(), 'packetviz-')) : ''
    const file = join(dir, filename)

    if (available) writeFileSync(file, writePcap(packets))

    afterAll(() => {
      if (dir) rmSync(dir, { recursive: true, force: true })
    })

    const tshark = (args: string[]): string =>
      execFileSync('tshark', ['-r', file, ...args], { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 })

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

    it('dissects every packet as Ethernet carrying ARP', () => {
      const protocols = tshark(['-T', 'fields', '-e', 'frame.protocols'])
        .split('\n')
        .filter((line) => line.length > 0)
      expect(protocols).toEqual(packets.map(() => 'eth:ethertype:arp'))
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

        for (const mapping of FIELD_MAP) {
          const node = Array.from(leafFields(decoded.tree)).find((n) => n.id === mapping.ours)
          expect(node, `packet ${index}: our decoder emitted no ${mapping.ours}`).toBeDefined()

          const raw = theirs.get(mapping.theirs)
          expect(raw, `packet ${index}: tshark emitted no ${mapping.theirs}`).toBeDefined()

          expect(
            ourValue(node as FieldNode, packet.frame, mapping.kind),
            `packet ${index}, field ${mapping.ours} vs tshark ${mapping.theirs}`,
          ).toBe(theirValue(raw as string, mapping.kind))
          comparisons += 1
        }
      })

      process.stdout.write(`  compared ${comparisons} field values across ${packets.length} packets against tshark\n`)
      expect(comparisons).toBe(packets.length * FIELD_MAP.length)
    })

    // Coverage — a new field cannot silently escape verification.
    it('maps every leaf field our decoder emits', () => {
      const mapped = new Set(FIELD_MAP.map((m) => m.ours))
      const emitted = new Set<string>()
      for (const packet of packets) {
        for (const node of leafFields(decodeFrame(packet.frame).tree)) emitted.add(node.id)
      }

      const unmapped = Array.from(emitted).filter((id) => !mapped.has(id))
      expect(
        unmapped,
        `these fields are decoded but never checked against Wireshark: ${unmapped.join(', ')}`,
      ).toEqual([])
    })

    it('maps no field tshark does not produce', () => {
      const json = JSON.parse(tshark(['-T', 'json'])) as {
        _source: { layers: Record<string, unknown> }
      }[]
      const theirs = new Set<string>()
      for (const packet of json) {
        for (const name of flattenLayers(packet._source.layers).keys()) theirs.add(name)
      }

      const stale = FIELD_MAP.filter((m) => !theirs.has(m.theirs)).map((m) => m.theirs)
      expect(stale, `mapping table names fields this tshark does not emit: ${stale.join(', ')}`).toEqual([])
    })
  })
}
