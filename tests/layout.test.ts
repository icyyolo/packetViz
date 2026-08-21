/**
 * The generic layout table and the concrete decode must never disagree.
 *
 * Both read the same `FieldSpec` arrays, so this is really a guard against
 * someone hand-writing offsets into the reference UI later: if a row's offset
 * stops matching the decoded field of the same id, the table has stopped being
 * derived and has started being typed.
 */

import { describe, expect, it } from 'vitest'
import { leafFields } from '../src/core/field.ts'
import { buildArpRequestFrame } from '../src/core/protocols/arp.ts'
import { ETH_MIN_FRAME_BYTES } from '../src/core/protocols/ethernet.ts'
import { decodeFrame, frameLayout } from '../src/core/registry.ts'

const packet = decodeFrame(
  buildArpRequestFrame({ mac: 'aa:bb:cc:00:00:01', ip: '10.0.0.1' }, '10.0.0.2'),
)

describe('frameLayout', () => {
  it('reads the protocol stack out of the frame, not out of a lesson', () => {
    expect(frameLayout(packet).map((section) => section.id)).toEqual(['eth', 'arp'])
  })

  it('agrees with the decode on every offset and width', () => {
    const decoded = new Map([...leafFields(packet.tree)].map((node) => [node.id, node]))
    const rows = frameLayout(packet).flatMap((section) => section.rows)

    expect(rows.length).toBeGreaterThan(0)
    for (const row of rows) {
      const node = decoded.get(row.spec.id)
      expect(node, `no decoded field for layout row ${row.spec.id}`).toBeDefined()
      expect(node?.byteStart, row.spec.id).toBe(row.byteStart)
      expect(node?.byteLength, row.spec.id).toBe(row.byteLength)
    }
  })

  it('covers every decoded header field, so no field is missing from the reference', () => {
    const rowIds = new Set(frameLayout(packet).flatMap((s) => s.rows).map((r) => r.spec.id))
    // Padding is not part of any header, so it is deliberately absent.
    const decodedIds = [...leafFields(packet.tree)]
      .map((node) => node.id)
      .filter((id) => id !== 'eth.padding')

    expect([...decodedIds].filter((id) => !rowIds.has(id))).toEqual([])
  })

  it('does not describe padding as a header field', () => {
    expect(packet.frame.length).toBe(ETH_MIN_FRAME_BYTES)
    const total = frameLayout(packet).reduce((sum, section) => sum + section.byteLength, 0)
    expect(total).toBeLessThan(ETH_MIN_FRAME_BYTES)
  })
})
