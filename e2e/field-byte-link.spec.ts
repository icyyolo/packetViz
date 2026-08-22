/**
 * The signature feature, checked exhaustively in a real browser.
 *
 * This replaces manual lesson criterion #4. For every lesson, every packet and
 * every leaf field of every packet: click the field, and assert the highlighted
 * hex cells are EXACTLY that field's byte range — not a superset, not a prefix.
 * Then the other direction, on a sample of bytes.
 *
 * The expected spans come from running our own decoder here in Node, so the test
 * compares the running app against the codec rather than against a fixture that
 * would have to be maintained alongside it.
 */

import { expect, test } from '@playwright/test'
import { leafFields, type DecodedPacket } from '../src/core/field.ts'
import { LESSONS } from '../src/lessons/index.ts'
import { compileScenario } from '../src/scenario/compile.ts'

/**
 * The reverse direction is a sample, not a second sweep: a DHCP frame is 297
 * bytes and clicking every one of them in four packets costs minutes for no new
 * information. Roughly this many bytes are checked per packet, spread evenly.
 */
const REVERSE_SAMPLES = 24

/** These tests are long by design — hundreds of real clicks in a real browser. */
const SWEEP_TIMEOUT_MS = 180_000

/** Byte offsets currently highlighted in the hex grid. */
async function selectedOffsets(page: import('@playwright/test').Page): Promise<number[]> {
  return page.$$eval('.hex-cell.is-selected', (cells) =>
    cells.map((cell) => Number(/Byte (\d+)/.exec(cell.getAttribute('aria-label') ?? '')?.[1] ?? -1)),
  )
}

/** The innermost decoded field covering a byte — what a click in the grid should select. */
function fieldAt(packet: DecodedPacket, offset: number): string | undefined {
  for (const node of leafFields(packet.tree)) {
    if (offset >= node.byteStart && offset < node.byteStart + node.byteLength) return node.id
  }
  return undefined
}

/**
 * Ground truth, typed by hand from the RFCs.
 *
 * The sweep below derives its expectations from our own decoder, which makes it
 * a check that the UI and the codec agree — it cannot catch a codec that is
 * wrong in the same way twice. (Proven: shifting `ip.ttl` by one byte in the
 * spec runner leaves the sweep green and fails the Wireshark differential.)
 * These few offsets are the independent anchor: a field, and where the standard
 * says its bytes are.
 */
const ANCHORS: Record<string, { id: string; start: number; length: number }[]> = {
  // Ethernet II, RFC 894: addresses then EtherType, no options, ever.
  common: [
    { id: 'eth.dst', start: 0, length: 6 },
    { id: 'eth.src', start: 6, length: 6 },
    { id: 'eth.type', start: 12, length: 2 },
  ],
  // ARP, RFC 826: htype 2, ptype 2, hlen 1, plen 1, opcode 2, then the addresses.
  arp: [
    { id: 'arp.opcode', start: 20, length: 2 },
    { id: 'arp.src.hw_mac', start: 22, length: 6 },
    { id: 'arp.src.proto_ipv4', start: 28, length: 4 },
    { id: 'arp.dst.proto_ipv4', start: 38, length: 4 },
  ],
  // IPv4 (RFC 791) at 14, UDP (RFC 768) at 34, DHCP at 42, and RFC 2131's magic
  // cookie 236 bytes into the DHCP message: 42 + 236 = 278.
  dhcp: [
    { id: 'ip.ttl', start: 22, length: 1 },
    { id: 'ip.src', start: 26, length: 4 },
    { id: 'udp.srcport', start: 34, length: 2 },
    { id: 'dhcp.id', start: 46, length: 4 },
    { id: 'dhcp.cookie', start: 278, length: 4 },
    { id: 'dhcp.opt.53', start: 282, length: 3 },
  ],
  // ICMP, RFC 792: type, code, checksum, then the identifier and sequence
  // number that only the echo messages define. IPv4 ends at 34, so the echo
  // data starts at 34 + 8.
  ping: [
    { id: 'ip.ttl', start: 22, length: 1 },
    { id: 'icmp.type', start: 34, length: 1 },
    { id: 'icmp.ident', start: 38, length: 2 },
    { id: 'icmp.seq', start: 40, length: 2 },
    { id: 'icmp.data', start: 42, length: 32 },
  ],
  // TCP, RFC 9293 §3.1: ports, then the two 32-bit numbers, then the byte the
  // flags share with the data offset, and the options from byte 20 of the
  // header. The SYN's first option is the maximum segment size.
  'tcp-handshake': [
    { id: 'tcp.srcport', start: 34, length: 2 },
    { id: 'tcp.seq', start: 38, length: 4 },
    { id: 'tcp.ack', start: 42, length: 4 },
    // A one-bit field highlights the byte it lives in — the second of the two
    // that hold the data offset and the flags.
    { id: 'tcp.flags.syn', start: 47, length: 1 },
    { id: 'tcp.window_size_value', start: 48, length: 2 },
    { id: 'tcp.opt.2', start: 54, length: 4 },
  ],
  // DNS, RFC 1035 §4.1: the header is twelve bytes from 42, so the question's
  // name starts at 54 and is one length byte per label plus the labels plus a
  // terminating zero — 21 bytes for files.corp.internal.
  dns: [
    { id: 'udp.srcport', start: 34, length: 2 },
    { id: 'dns.id', start: 42, length: 2 },
    { id: 'dns.count.queries', start: 46, length: 2 },
    { id: 'dns.qry.name', start: 54, length: 21 },
    { id: 'dns.qry.type', start: 75, length: 2 },
    { id: 'dns.qry.class', start: 77, length: 2 },
  ],
}

function anchorsFor(slug: string): { id: string; start: number; length: number }[] {
  const stack = slug.startsWith('arp') ? ANCHORS.arp : (ANCHORS[slug] ?? ANCHORS.dhcp)
  return [...(ANCHORS.common ?? []), ...(stack ?? [])]
}

for (const lesson of LESSONS) {
  test(`${lesson.slug}: hand-checked offsets from the RFCs land where they should`, async ({
    page,
  }) => {
    await page.goto(`#/lesson/${lesson.slug}`)
    await expect(page.locator('[role="tree"]')).toBeVisible()

    for (const anchor of anchorsFor(lesson.slug)) {
      await page.locator(`[data-field-id="${anchor.id}"]`).first().click()
      const expected = Array.from({ length: anchor.length }, (_x, i) => anchor.start + i)
      expect(await selectedOffsets(page), `${lesson.slug} ${anchor.id}`).toEqual(expected)
    }
  })

  test(`${lesson.slug}: every leaf field highlights exactly its own bytes`, async ({ page }) => {
    test.setTimeout(SWEEP_TIMEOUT_MS)
    const timeline = compileScenario(lesson.scenario)
    let checked = 0

    await page.goto(`#/lesson/${lesson.slug}`)
    await expect(page.locator('[role="tree"]')).toBeVisible()

    for (const [index, packet] of timeline.packets.entries()) {
      // Packets are switched by clicking their tab, not by re-navigating: after
      // mount the URL is an OUTPUT of the selection, so changing the hash in
      // place would leave the page showing the packet it already had.
      await page.locator('.packet-tab').nth(index).click()

      // A field id can legitimately repeat within one packet — a TCP header
      // carries three No-Operation options, and a malformed DHCP message can
      // repeat an option code. The rows are in wire order, so the nth row with
      // an id is the nth node with it; clicking `.first()` every time would
      // check the first one three times and the other two never.
      const seen = new Map<string, number>()
      for (const node of leafFields(packet.tree)) {
        const occurrence = seen.get(node.id) ?? 0
        seen.set(node.id, occurrence + 1)
        await page.locator(`[data-field-id="${node.id}"]`).nth(occurrence).click()

        const expected = Array.from({ length: node.byteLength }, (_x, i) => node.byteStart + i)
        expect(await selectedOffsets(page), `${lesson.slug} packet ${index} field ${node.id}`).toEqual(
          expected,
        )
        checked += 1
      }
    }

    expect(checked).toBeGreaterThan(0)
    // eslint-disable-next-line no-console
    console.log(`  ${lesson.slug}: ${checked} field-to-byte assertions`)
  })

  test(`${lesson.slug}: clicking a byte selects the field that owns it`, async ({ page }) => {
    test.setTimeout(SWEEP_TIMEOUT_MS)
    const timeline = compileScenario(lesson.scenario)
    let checked = 0

    await page.goto(`#/lesson/${lesson.slug}`)
    await expect(page.locator('.hex-grid')).toBeVisible()

    for (const [index, packet] of timeline.packets.entries()) {
      await page.locator('.packet-tab').nth(index).click()

      const stride = Math.max(1, Math.ceil(packet.frame.length / REVERSE_SAMPLES))
      for (let offset = 0; offset < packet.frame.length; offset += stride) {
        const expectedId = fieldAt(packet, offset)
        if (expectedId === undefined) continue

        const byte = packet.frame[offset] ?? 0
        await page.getByLabel(`Byte ${offset}, value 0x${byte.toString(16).padStart(2, '0')}`).click()

        const selected = await page.locator('.tree-row.is-selected').getAttribute('data-field-id')
        expect(selected, `${lesson.slug} packet ${index} byte ${offset}`).toBe(expectedId)
        checked += 1
      }
    }

    expect(checked).toBeGreaterThan(0)
    // eslint-disable-next-line no-console
    console.log(`  ${lesson.slug}: ${checked} byte-to-field assertions`)
  })
}
