/**
 * Protocol dispatch, and `decodeFrame` — the single entry point every view uses.
 *
 * `decodeFrame` is a TOTAL function. For any `Uint8Array`, including empty,
 * truncated, or adversarial input, it:
 *
 *   1. never throws — it returns whatever it could parse plus a `Problem`;
 *   2. never loops forever — every variable-length loop advances by at least one
 *      byte per iteration or bails with a `Problem`;
 *   3. never allocates unbounded — no allocation is sized from an untrusted
 *      length field without first clamping it to the remaining buffer;
 *   4. never reads out of bounds — undecodable trailing bytes become a single
 *      raw `FieldNode`, not a crash.
 *
 * This is not defensive polish: Phase 7 imports .pcap files the user did not
 * create, and Phase 3.5 lets the user edit bytes by hand. `tests/fuzz.property.test.ts`
 * enforces all four clauses.
 */

import type { DecodeResult, DecodedPacket, FieldNode, Problem } from './field.ts'
import { formatHexBytes, hex } from './format.ts'
import { decodeArp } from './protocols/arp.ts'
import { ETHER_TYPE, decodeEthernet, paddingNode } from './protocols/ethernet.ts'

export type ProtocolDecoder = (frame: Uint8Array, offset: number) => DecodeResult

export type ProtocolEntry = {
  id: string
  name: string
  decode: ProtocolDecoder
}

/**
 * EtherType -> decoder. Membership here is what "implemented" means; Phase 8's
 * concept map derives its greyed-out blocks from this table rather than from a
 * hand-maintained boolean.
 */
export const BY_ETHER_TYPE: ReadonlyMap<number, ProtocolEntry> = new Map([
  [ETHER_TYPE.ARP, { id: 'arp', name: 'ARP', decode: decodeArp }],
])

export function decodeFrame(frame: Uint8Array): DecodedPacket {
  const ethernet = decodeEthernet(frame)
  const nodes: FieldNode[] = [...ethernet.nodes]
  const problems: Problem[] = [...ethernet.problems]
  let summary = ethernet.summary
  let offset = ethernet.byteLength

  if (problems.length === 0) {
    const entry =
      ethernet.etherType === undefined ? undefined : BY_ETHER_TYPE.get(ethernet.etherType)

    if (entry !== undefined) {
      const payload = entry.decode(frame, offset)
      nodes.push(...payload.nodes)
      problems.push(...payload.problems)
      summary = payload.summary
      offset += payload.byteLength
    } else if (offset < frame.length) {
      nodes.push(undecodedNode(frame, offset))
      problems.push({
        severity: 'warning',
        message: `No decoder for EtherType ${hex(ethernet.etherType ?? 0, 4)}; ${frame.length - offset} byte(s) left undecoded`,
        byteStart: offset,
        byteLength: frame.length - offset,
      })
      summary = `${summary} (undecoded payload)`
      offset = frame.length
    }
  }

  if (problems.length === 0) {
    const padding = paddingNode(frame, offset)
    if (padding !== undefined) nodes.push(padding)
  }

  return { frame, tree: nodes, summary, problems }
}

/**
 * Undecodable bytes stay linked to the hex view as one raw field, so an
 * unsupported protocol degrades to "here are the bytes" instead of a blank pane.
 */
function undecodedNode(frame: Uint8Array, offset: number): FieldNode {
  const raw = frame.subarray(offset)
  return {
    id: 'data',
    name: 'Payload (no decoder)',
    byteStart: offset,
    byteLength: raw.length,
    raw,
    value: formatHexBytes(raw.subarray(0, 16)) + (raw.length > 16 ? ' ...' : ''),
    description: 'PacketViz has no decoder registered for this EtherType, so the payload is shown as raw bytes.',
  }
}
