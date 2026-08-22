/**
 * The generated header diagram, checked against the thing it claims to draw.
 *
 * A diagram that does not add up to the header's real size is worse than no
 * diagram: it looks authoritative and is wrong. So every box of every row is
 * summed and compared with the spec table's own byte count.
 */

import { describe, expect, it } from 'vitest'
import { describeProtocols } from '../src/core/registry.ts'
import { specBytes } from '../src/core/spec.ts'
import { ROW_BITS, diagramRows } from '../src/pages/diagram.ts'

const implemented = describeProtocols().filter((protocol) => protocol.implemented)

describe('header diagrams', () => {
  it('draws one for every implemented protocol', () => {
    expect(implemented.map((protocol) => protocol.id)).toEqual(['eth', 'arp', 'ip', 'udp', 'dhcp'])
    for (const protocol of implemented) {
      expect(diagramRows(protocol.specs).length, protocol.id).toBeGreaterThan(0)
    }
  })

  it('has boxes that sum to the true header size', () => {
    for (const protocol of implemented) {
      const drawn = diagramRows(protocol.specs)
        .flatMap((row) => row.cells)
        .reduce((bits, cell) => bits + cell.bits, 0)

      expect(drawn / 8, `${protocol.id} diagram`).toBe(specBytes(protocol.specs))
    }
  })

  it('never overfills a 32-bit row', () => {
    for (const protocol of implemented) {
      for (const row of diagramRows(protocol.specs)) {
        const bits = row.cells.reduce((sum, cell) => sum + cell.bits, 0)
        const elided = row.cells.some((cell) => cell.elided)
        expect(elided || bits <= ROW_BITS, `${protocol.id} row at bit ${row.bitStart}`).toBe(true)
      }
    }
  })

  it('splits a field that crosses a row boundary, and marks the continuation', () => {
    // A MAC address is 48 bits: 32 in one row, 16 in the next, exactly as RFC 894
    // draws it.
    const rows = diagramRows(describeProtocols()[0]!.specs)
    const destination = rows.flatMap((row) => row.cells).filter((cell) => cell.spec.id === 'eth.dst')

    expect(destination.map((cell) => cell.bits)).toEqual([32, 16])
    expect(destination.map((cell) => cell.first)).toEqual([true, false])
    expect(destination[0]?.continues).toBe(true)
  })

  it('elides a field too large to draw, rather than repeating identical rows', () => {
    const dhcp = implemented.find((protocol) => protocol.id === 'dhcp')!
    const elided = diagramRows(dhcp.specs)
      .flatMap((row) => row.cells)
      .filter((cell) => cell.elided)

    // sname (64 bytes) and file (128): 48 rows of identical boxes avoided.
    // chaddr's 10 bytes of padding are big enough to elide but do not start on a
    // 32-bit boundary — the client MAC ends mid-row — so they wrap normally
    // instead, which is the fallback the layout code chooses on purpose.
    expect(elided.map((cell) => cell.spec.id)).toEqual(['dhcp.server', 'dhcp.file'])
    expect(elided.every((cell) => cell.bits > 64)).toBe(true)
  })
})
