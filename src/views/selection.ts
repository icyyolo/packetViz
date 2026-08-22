/**
 * Selection state: what is selected, and what is merely hovered.
 *
 * The state holds field IDs, not byte spans. Spans are derived from the current
 * `DecodedPacket` via `spanOf()` on every render, so a selection survives a
 * re-decode — the point of Phase 3.5, where editing a byte rebuilds the whole
 * tree while the user's selection must stay put — and a deep link only has to
 * carry `?f=arp.opcode`.
 *
 * An id alone is not quite enough, though: a field id may legitimately appear
 * more than once in one packet. A real TCP SYN carries three No-Operation
 * options, all of them `tcp.opt.1`, and a malformed DHCP message can repeat an
 * option code. So selection is an id AND an occurrence — the nth node with that
 * id, in wire order — and clicking the third No-Operation highlights the third
 * one's byte rather than the first one's. A deep link still carries only the id
 * and resolves to occurrence 0, because a URL should stay readable.
 *
 * The context and hook live here rather than beside the provider component so
 * the provider file exports components only, which is what fast refresh wants.
 */

import { createContext, useContext } from 'react'
import {
  findField,
  leafFields,
  walkFields,
  type DecodedPacket,
  type FieldNode,
} from '../core/field.ts'

export type Span = { start: number; length: number }

export type SelectionState = {
  packetIndex: number
  selectedFieldId: string | null
  /** Which node with that id: 0 unless the id repeats within the packet. */
  selectedOccurrence: number
  hoveredFieldId: string | null
  hoveredOccurrence: number
}

export type SelectionApi = SelectionState & {
  selectPacket: (index: number) => void
  selectField: (fieldId: string | null, occurrence?: number) => void
  hoverField: (fieldId: string | null, occurrence?: number) => void
}

export const SelectionContext = createContext<SelectionApi | null>(null)

export function useSelection(): SelectionApi {
  const value = useContext(SelectionContext)
  if (value === null) throw new Error('useSelection must be used inside a SelectionProvider')
  return value
}

/** Byte span of a field in this packet, or `null` if it is not present. */
export function spanOf(
  packet: DecodedPacket,
  fieldId: string | null,
  occurrence = 0,
): Span | null {
  const node = nodeOf(packet, fieldId, occurrence)
  if (node === undefined) return null
  return { start: node.byteStart, length: node.byteLength }
}

export function nodeOf(
  packet: DecodedPacket,
  fieldId: string | null,
  occurrence = 0,
): FieldNode | undefined {
  if (fieldId === null) return undefined
  if (occurrence <= 0) return findField(packet.tree, fieldId)

  let seen = 0
  for (const node of walkFields(packet.tree)) {
    if (node.id !== fieldId) continue
    if (seen === occurrence) return node
    seen += 1
  }
  // A deep link, or a re-decode that removed a repeat, can ask for an
  // occurrence that is no longer there. Falling back to the first is what the
  // rest of the app already does with an id it cannot find.
  return findField(packet.tree, fieldId)
}

export function inSpan(span: Span | null, offset: number): boolean {
  return span !== null && offset >= span.start && offset < span.start + span.length
}

/**
 * The innermost decoded field covering a byte — what a click in the hex grid
 * selects — together with which occurrence of its id it is, so that clicking a
 * byte of the third No-Operation option selects that one and not the first.
 */
export function fieldAtOffset(
  packet: DecodedPacket,
  offset: number,
): { node: FieldNode; occurrence: number } | undefined {
  let found: FieldNode | undefined
  for (const node of leafFields(packet.tree)) {
    if (offset >= node.byteStart && offset < node.byteStart + node.byteLength) {
      found = node
      break
    }
  }
  if (found === undefined) return undefined

  let occurrence = 0
  for (const node of walkFields(packet.tree)) {
    if (node === found) break
    if (node.id === found.id) occurrence += 1
  }
  return { node: found, occurrence }
}
