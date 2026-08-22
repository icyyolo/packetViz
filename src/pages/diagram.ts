/**
 * Laying a spec table out as an RFC-style header diagram.
 *
 * Every RFC draws its header as 32-bit rows of boxes, and that picture is the
 * fastest way to see a header's shape. Ours is derived from the same
 * `FieldSpec` array the decoder runs, so it cannot drift: add a field to a spec
 * and the diagram changes with no edit to the drawing code.
 *
 * Two things the format forces:
 *
 *   - a field that crosses a 32-bit boundary is drawn as two boxes, the way an
 *     RFC draws a 48-bit MAC address across two rows;
 *   - a field too large to draw honestly — DHCP's 64-byte `sname`, its 128-byte
 *     `file` — becomes one labelled block saying how many bytes it stands for.
 *     Drawing 32 identical rows would be accurate and useless.
 *
 * Pure and component-free, so `tests/reference.test.ts` can assert that the
 * boxes add up to the header's true size.
 */

import type { FieldSpec } from '../core/spec.ts'

export const ROW_BITS = 32

/** Above this width a field is elided rather than drawn to scale. Two full rows. */
const ELIDE_BITS = 64

export type DiagramCell = {
  spec: FieldSpec
  /** Bits this box covers. */
  bits: number
  /** False for the continuation of a field that crossed a row boundary. */
  first: boolean
  /** True when the field continues into the next row. */
  continues: boolean
  /** A whole-row stand-in for a field too big to draw. */
  elided: boolean
}

export type DiagramRow = {
  /** Bit offset of the row's first bit, from the start of the header. */
  bitStart: number
  cells: DiagramCell[]
}

/**
 * Lay a spec table out as 32-bit rows. Pure, so `tests/reference.test.ts` can
 * assert that the boxes add up to the header's true size.
 */
export function diagramRows(specs: readonly FieldSpec[]): DiagramRow[] {
  const rows: DiagramRow[] = []
  let bitCursor = 0

  const rowFor = (bit: number): DiagramRow => {
    const bitStart = bit - (bit % ROW_BITS)
    const last = rows[rows.length - 1]
    if (last !== undefined && last.bitStart === bitStart) return last
    const row: DiagramRow = { bitStart, cells: [] }
    rows.push(row)
    return row
  }

  for (const spec of specs) {
    // Elision only works on a row boundary; every oversized field in our specs
    // starts on one, and anything that did not would simply wrap instead.
    if (spec.bits > ELIDE_BITS && bitCursor % ROW_BITS === 0) {
      rows.push({
        bitStart: bitCursor,
        cells: [{ spec, bits: spec.bits, first: true, continues: false, elided: true }],
      })
      bitCursor += spec.bits
      continue
    }

    let remaining = spec.bits
    let first = true
    while (remaining > 0) {
      const room = ROW_BITS - (bitCursor % ROW_BITS)
      const bits = Math.min(remaining, room)
      rowFor(bitCursor).cells.push({
        spec,
        bits,
        first,
        continues: remaining > bits,
        elided: false,
      })
      bitCursor += bits
      remaining -= bits
      first = false
    }
  }

  return rows
}
