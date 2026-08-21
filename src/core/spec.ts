/**
 * The declarative half of the codec.
 *
 * One `FieldSpec` table per fixed-layout protocol header. The table drives
 * decoding AND every piece of explainer UI (field tree, detail panel, generated
 * reference page), so a field is described in exactly one place.
 *
 * The imperative half — the encoders, and DHCP's TLV option loop — is written by
 * hand against the same wire constants. The two directions are reconciled by
 * round-trip property tests, not by a framework that claims to be both.
 */

import { readBits } from './bytes.ts'
import type { FieldNode, Problem } from './field.ts'

export type DecodeCtx = {
  frame: Uint8Array
  /**
   * Numeric value of the field being rendered, big-endian.
   * `NaN` for fields wider than 32 bits (MAC addresses, IPv4 addresses read as
   * bytes), so renderers for those must use `raw`.
   */
  num: number
  /** Numeric values of fields already decoded in this run, keyed by field id. */
  values: ReadonlyMap<string, number>
}

export type FieldSpec = {
  id: string
  name: string
  /** Sub-byte widths are supported; the runner tracks a bit cursor. */
  bits: number
  render: (raw: Uint8Array, ctx: DecodeCtx) => string
  /** Shown in the detail panel and on the reference page. Required — a field may not ship unexplained. */
  description: string
  /** e.g. "RFC 826 §2". */
  reference?: string
  /** Enum dictionary: opcodes, EtherTypes, option codes. */
  values?: Record<number, string>
}

export type SpecRun = {
  nodes: FieldNode[]
  problems: Problem[]
  values: ReadonlyMap<string, number>
  /** Bytes consumed from `offset`. Short of the spec's full width if truncated. */
  byteLength: number
}

/** Total width of a spec table in bytes. */
export function specBytes(specs: readonly FieldSpec[]): number {
  return Math.ceil(specs.reduce((sum, spec) => sum + spec.bits, 0) / 8)
}

/**
 * Decode a fixed-layout header. Total: for any frame and any offset this
 * returns, never throws and never reads out of bounds. Truncation stops the run
 * and emits one `Problem` naming the field that did not fit.
 */
export function runSpec(
  specs: readonly FieldSpec[],
  frame: Uint8Array,
  offset: number,
): SpecRun {
  const nodes: FieldNode[] = []
  const problems: Problem[] = []
  const values = new Map<string, number>()
  const startBit = Math.max(0, offset) * 8
  let bitCursor = startBit

  for (const spec of specs) {
    const byteStart = bitCursor >> 3
    const byteEnd = Math.ceil((bitCursor + spec.bits) / 8)
    if (byteEnd > frame.length) {
      problems.push({
        severity: 'error',
        message: `Truncated at ${spec.name}: needs ${byteEnd - byteStart} byte(s) at offset ${byteStart}, but the frame is ${frame.length} bytes`,
        byteStart: Math.min(byteStart, frame.length),
        byteLength: Math.max(0, frame.length - byteStart),
      })
      break
    }

    const raw = frame.subarray(byteStart, byteEnd)
    const num = readBits(frame, bitCursor, spec.bits)
    const node: FieldNode = {
      id: spec.id,
      name: spec.name,
      byteStart,
      byteLength: byteEnd - byteStart,
      raw,
      value: spec.render(raw, { frame, num, values }),
      description: spec.description,
    }
    if (spec.reference !== undefined) node.reference = spec.reference
    if (bitCursor % 8 !== 0 || spec.bits % 8 !== 0) {
      node.bitOffset = bitCursor % 8
      node.bitLength = spec.bits
    }

    nodes.push(node)
    if (Number.isFinite(num)) values.set(spec.id, num)
    bitCursor += spec.bits
  }

  return {
    nodes,
    problems,
    values,
    byteLength: Math.ceil(bitCursor / 8) - Math.max(0, offset),
  }
}

/**
 * Renderer for enumerated fields: "1 (Request)", or "7 (unknown)" when the
 * value is not in the dictionary. Decoding must never hide an unknown value.
 */
export function enumRender(
  dictionary: Record<number, string>,
  formatNumber: (value: number) => string = (value) => value.toString(10),
): FieldSpec['render'] {
  return (_raw, ctx) => {
    const name = dictionary[ctx.num]
    return `${formatNumber(ctx.num)} (${name ?? 'unknown'})`
  }
}
