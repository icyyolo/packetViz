/**
 * The other half of the correctness claim.
 *
 * Every other test in this project checks our decoder against bytes our own
 * encoder produced. That proves the two halves agree with each other and with
 * Wireshark, but the capture itself is still ours. Here the file is somebody
 * else's: written by Wireshark's own tools, holding frames from hardware we do
 * not have, with addresses and vendors that appear nowhere in this repository.
 *
 * Two independent sources, because they test different things:
 *
 *   - `editcap -F pcap` rewrites our own capture with Wireshark's writer, which
 *     is how the reader gets held to the OTHER byte order (editcap writes
 *     little-endian on x86; we write big-endian);
 *   - `text2pcap` assembles frames from a hex dump typed by hand into this file,
 *     so the bytes never passed through our encoders at all.
 *
 * Both are then read with `readPcap`, decoded, and compared field by field
 * against what tshark reads out of the very same file.
 */

import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { leafFields } from '../src/core/field.ts'
import { frameAt, readPcap, type PcapCapture } from '../src/core/pcap/read.ts'
import { writePcap } from '../src/core/pcap/write.ts'
import { decodeFrame } from '../src/core/registry.ts'
import { dhcpExchange } from './fixtures.ts'
import { FIELD_MAP, flattenLayers, ourValue, theirValue, tsharkAvailable } from './tshark.ts'

/**
 * Two ARP frames typed out by hand from a home network: a Micro-Star NIC asking
 * for its DrayTek router, and the router answering. Nothing here came from our
 * encoders — the vendor OUIs and the 192.168.1.0/24 addressing appear nowhere
 * else in this project. The reply appears twice, at 54 and at 60 bytes, because
 * that is the pair that separates a trailer from padding — see `paddingNode`.
 */
const FOREIGN_ARP_HEXDUMP = `000000  ff ff ff ff ff ff d4 3d 7e c5 1a 2b 08 06 00 01
000010  08 00 06 04 00 01 d4 3d 7e c5 1a 2b c0 a8 01 6a
000020  00 00 00 00 00 00 c0 a8 01 01

000000  d4 3d 7e c5 1a 2b 00 1d aa 3f 20 7c 08 06 00 01
000010  08 00 06 04 00 02 00 1d aa 3f 20 7c c0 a8 01 01
000020  d4 3d 7e c5 1a 2b c0 a8 01 6a 00 00 00 00 00 00
000030  00 00 00 00 00 00

000000  d4 3d 7e c5 1a 2b 00 1d aa 3f 20 7c 08 06 00 01
000010  08 00 06 04 00 02 00 1d aa 3f 20 7c c0 a8 01 01
000020  d4 3d 7e c5 1a 2b c0 a8 01 6a 00 00 00 00 00 00
000030  00 00 00 00 00 00 00 00 00 00 00 00
`

/**
 * `-h`, not `-v`: in Wireshark 3.6 `editcap -v` means "verbose" and exits 1
 * without input files, which would have silently skipped this whole test.
 */
function toolAvailable(tool: string): boolean {
  try {
    execFileSync(tool, ['-h'], { stdio: 'ignore' })
    return true
  } catch {
    return false
  }
}

const available = tsharkAvailable() && toolAvailable('text2pcap') && toolAvailable('editcap')
const required = process.env.REQUIRE_TSHARK === '1'

if (!available && !required) {
  process.stderr.write(
    '\n  ⚠  tshark/text2pcap/editcap not all on PATH — SKIPPING the foreign-capture\n' +
      '     import test. It is the only check that our reader handles a file this\n' +
      '     project did not write. CI sets REQUIRE_TSHARK=1 to make this a failure.\n\n',
  )
}

describe('importing a capture from somewhere else', () => {
  it('has the Wireshark tools available when REQUIRE_TSHARK=1', () => {
    if (required) {
      expect(available, 'REQUIRE_TSHARK=1 but tshark/text2pcap/editcap are not all on PATH').toBe(
        true,
      )
    }
  })

  const dir = available ? mkdtempSync(join(tmpdir(), 'packetviz-import-')) : ''
  afterAll(() => {
    if (dir) rmSync(dir, { recursive: true, force: true })
  })

  it.skipIf(!available)(
    'reads back a capture Wireshark rewrote, in the byte order we never write',
    () => {
      const ours = join(dir, 'ours.pcap')
      const theirs = join(dir, 'editcap.pcap')
      const packets = dhcpExchange()
      writeFileSync(ours, writePcap(packets))
      execFileSync('editcap', ['-F', 'pcap', ours, theirs])

      const capture = expectRead(readFileSync(theirs))

      // editcap on x86 writes d4c3b2a1. Our writer never produces that, so this
      // is the reader's endianness support meeting a real file rather than a
      // synthetic one.
      expect(capture.byteOrder).toBe('little-endian')
      expect(capture.totalRecords).toBe(packets.length)
      capture.records.forEach((record, index) => {
        expect(Array.from(frameAt(capture, record))).toEqual(Array.from(packets[index]!.frame))
      })

      const compared = compareWithTshark(theirs, capture)
      expect(compared).toBeGreaterThan(100)
    },
  )

  it.skipIf(!available)('decodes hand-typed foreign ARP frames to the values tshark reads', () => {
    const source = join(dir, 'foreign.txt')
    const file = join(dir, 'foreign.pcap')
    writeFileSync(source, FOREIGN_ARP_HEXDUMP)
    execFileSync('text2pcap', ['-q', source, file])

    const capture = expectRead(readFileSync(file))
    expect(capture.byteOrder).toBe('little-endian')
    expect(capture.records).toHaveLength(3)

    expect(capture.records.map((record) => record.inclLen)).toEqual([42, 54, 60])

    const decoded = capture.records.map((record) => decodeFrame(frameAt(capture, record)))
    expect(decoded.map((packet) => packet.problems)).toEqual([[], [], []])
    expect(decoded[0]?.summary).toBe('Who has 192.168.1.1? Tell 192.168.1.106')
    expect(decoded[1]?.summary).toBe('192.168.1.1 is at 00:1d:aa:3f:20:7c')

    // The same twelve zero bytes, named differently by their frame's length —
    // and tshark, asked about the same file below, draws the line in the same
    // place. The 42-byte request has neither.
    expect(idsOf(decoded[0])).not.toContain('eth.trailer')
    expect(idsOf(decoded[1])).toContain('eth.trailer')
    expect(idsOf(decoded[2])).toContain('eth.padding')

    const compared = compareWithTshark(file, capture)
    expect(compared).toBeGreaterThan(20)
  })
})

function idsOf(packet: { tree: Parameters<typeof leafFields>[0] } | undefined): string[] {
  return packet === undefined ? [] : Array.from(leafFields(packet.tree), (node) => node.id)
}

function expectRead(bytes: Buffer): PcapCapture {
  const result = readPcap(new Uint8Array(bytes))
  if (!result.ok) throw new Error(`readPcap refused a valid capture: ${result.message}`)
  return result.capture
}

/**
 * Field-for-field agreement between our decode of a file and tshark's, using
 * the same mapping table the generated-traffic differential uses. Returns the
 * number of comparisons so a test can refuse to pass on an empty check.
 */
function compareWithTshark(file: string, capture: PcapCapture): number {
  const json = JSON.parse(
    execFileSync(
      'tshark',
      ['-r', file, '-o', 'ip.check_checksum:TRUE', '-o', 'udp.check_checksum:TRUE', '-T', 'json'],
      { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 },
    ),
  ) as { _source: { layers: Record<string, unknown> } }[]

  expect(json).toHaveLength(capture.records.length)

  let comparisons = 0
  capture.records.forEach((record, index) => {
    const frame = frameAt(capture, record)
    const decoded = decodeFrame(frame)
    const theirs = flattenLayers(json[index]?._source.layers ?? {})
    const leaves = new Map(Array.from(leafFields(decoded.tree)).map((node) => [node.id, node]))

    for (const mapping of FIELD_MAP) {
      const node = leaves.get(mapping.ours)
      if (node === undefined) continue

      const raw = theirs.get(mapping.theirs)
      expect(raw, `packet ${index}: tshark emitted no ${mapping.theirs}`).toBeDefined()
      expect(
        ourValue(node, frame, mapping),
        `packet ${index}, field ${mapping.ours} vs tshark ${mapping.theirs}`,
      ).toBe(theirValue(raw as string, mapping.kind))
      comparisons += 1
    }
  })

  process.stdout.write(
    `  compared ${comparisons} field values against tshark on an imported ${capture.byteOrder} capture\n`,
  )
  return comparisons
}
