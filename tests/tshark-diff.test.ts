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
 * The mapping table, and the two functions that put our values and tshark's into
 * the same shape, live in `tests/tshark.ts` — `import.test.ts` asks the same
 * questions of a capture this project did not write, and shares them.
 */

import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { leafFields, type FieldNode } from '../src/core/field.ts'
import { writePcap } from '../src/core/pcap/write.ts'
import { decodeFrame } from '../src/core/registry.ts'
import { arpSpoofingScenario } from '../src/lessons/arp-spoofing/scenario.ts'
import { dhcpScenario } from '../src/lessons/dhcp/scenario.ts'
import type { PcapPacket } from '../src/core/pcap/write.ts'
import { arpExchange, arpRequestFrame, dhcpExchange, lessonCapture } from './fixtures.ts'
import {
  FIELD_MAP,
  OPTION_MAP,
  OPTION_STRUCTURE,
  flattenLayers,
  isMappedOptionValue,
  optionCode,
  optionNodes,
  ourOptionValue,
  ourValue,
  theirValue,
  tsharkAvailable,
} from './tshark.ts'

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

  // The lesson's own capture, byte for byte as the export button writes it.
  differential(
    'on the DHCP lesson capture',
    'dhcp-lesson.pcap',
    lessonCapture(dhcpScenario),
    [],
    'eth:ethertype:ip:udp:dhcp',
  )

  it.skipIf(!available)('sees the lesson as a DISCOVER, OFFER, REQUEST, ACK exchange', () => {
    const dir = mkdtempSync(join(tmpdir(), 'packetviz-dora-'))
    const file = join(dir, 'dora.pcap')
    writeFileSync(file, writePcap(lessonCapture(dhcpScenario)))

    // Plan step 5.3, run as a test rather than by hand: message types 1, 2, 3, 5
    // in order, read by Wireshark out of the file a visitor can download.
    const types = execFileSync('tshark', ['-r', file, '-T', 'fields', '-e', 'dhcp.option.dhcp'], {
      encoding: 'utf8',
    })
      .split('\n')
      .filter((line) => line.length > 0)
    rmSync(dir, { recursive: true, force: true })

    expect(types).toEqual(['1', '2', '3', '5'])
  })

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
