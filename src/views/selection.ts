/**
 * Selection state: what is selected, and what is merely hovered.
 *
 * The state holds field IDs, not byte spans. Spans are derived from the current
 * `DecodedPacket` via `spanOf()` on every render, so a selection survives a
 * re-decode — the point of Phase 3.5, where editing a byte rebuilds the whole
 * tree while the user's selection must stay put — and a deep link only has to
 * carry `?f=arp.opcode`.
 *
 * The context and hook live here rather than beside the provider component so
 * the provider file exports components only, which is what fast refresh wants.
 */

import { createContext, useContext } from 'react'
import { findField, leafFields, type DecodedPacket, type FieldNode } from '../core/field.ts'

export type Span = { start: number; length: number }

export type SelectionState = {
  packetIndex: number
  selectedFieldId: string | null
  hoveredFieldId: string | null
}

export type SelectionApi = SelectionState & {
  selectPacket: (index: number) => void
  selectField: (fieldId: string | null) => void
  hoverField: (fieldId: string | null) => void
}

export const SelectionContext = createContext<SelectionApi | null>(null)

export function useSelection(): SelectionApi {
  const value = useContext(SelectionContext)
  if (value === null) throw new Error('useSelection must be used inside a SelectionProvider')
  return value
}

/** Byte span of a field in this packet, or `null` if it is not present. */
export function spanOf(packet: DecodedPacket, fieldId: string | null): Span | null {
  if (fieldId === null) return null
  const node = findField(packet.tree, fieldId)
  if (node === undefined) return null
  return { start: node.byteStart, length: node.byteLength }
}

export function nodeOf(packet: DecodedPacket, fieldId: string | null): FieldNode | undefined {
  if (fieldId === null) return undefined
  return findField(packet.tree, fieldId)
}

export function inSpan(span: Span | null, offset: number): boolean {
  return span !== null && offset >= span.start && offset < span.start + span.length
}

/** The innermost decoded field covering a byte — what a click in the hex grid selects. */
export function fieldAtOffset(packet: DecodedPacket, offset: number): FieldNode | undefined {
  for (const node of leafFields(packet.tree)) {
    if (offset >= node.byteStart && offset < node.byteStart + node.byteLength) return node
  }
  return undefined
}
