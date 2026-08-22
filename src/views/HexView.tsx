/**
 * Layer 4: the bytes.
 *
 * This is the only view that shows the source of truth directly. Every other
 * layer is a projection of the same buffer, so a byte highlighted here and a
 * field highlighted in the tree are the same fact seen twice.
 *
 * Accessibility: a roving-tabindex grid. One cell is tabbable at a time; arrow
 * keys move, Enter or Space selects. Highlighting never depends on hue alone —
 * selected cells also carry an outline and an underline.
 */

import { useCallback, useEffect, useRef, useState } from 'react'
import type { DecodedPacket, Problem } from '../core/field.ts'
import { fieldAtOffset, inSpan, spanOf, useSelection, type Span } from './selection.ts'

const BYTES_PER_ROW = 16

/**
 * Header boundaries are the thing a hex dump hides worst. Each top-level node of
 * the decode — Ethernet, the payload protocol, the padding that belongs to
 * neither — tints its own byte range, so the reader can see that ARP starts at
 * byte 14 without clicking anything. The colours cycle through a small set and
 * carry a legend, and they are a background wash only: selection still owns the
 * outline and the underline, so nothing here depends on hue.
 */
type Section = {
  id: string
  name: string
  byteStart: number
  byteLength: number
  index: number
}

function sectionsOf(packet: DecodedPacket): Section[] {
  return packet.tree.map((node, index) => ({
    id: node.id,
    name: node.name,
    byteStart: node.byteStart,
    byteLength: node.byteLength,
    index,
  }))
}

function sectionAt(sections: readonly Section[], offset: number): Section | undefined {
  return sections.find(
    (section) => offset >= section.byteStart && offset < section.byteStart + section.byteLength,
  )
}

export type HexViewProps = {
  packet: DecodedPacket
  /**
   * Makes the grid writable. The handler receives a byte offset and a new value
   * and is expected to produce a fresh buffer; this view never mutates
   * `packet.frame`, which is the scenario's own array.
   */
  onEditByte?: (offset: number, value: number) => void
  /** The unedited bytes, so a changed byte can be marked as changed. */
  baseline?: Uint8Array
}

export function HexView({ packet, onEditByte, baseline }: HexViewProps) {
  const { selectedFieldId, selectedOccurrence, hoveredFieldId, hoveredOccurrence, selectField, hoverField } =
    useSelection()
  const frame = packet.frame
  const selected = spanOf(packet, selectedFieldId, selectedOccurrence)
  const hovered = spanOf(packet, hoveredFieldId, hoveredOccurrence)
  const sections = sectionsOf(packet)

  const [requestedFocus, setFocusOffset] = useState(0)
  /** First digit of a two-digit entry, waiting for its partner. */
  const [pending, setPending] = useState<{ offset: number; nibble: number } | null>(null)
  const cells = useRef<(HTMLDivElement | null)[]>([])
  const shouldFocus = useRef(false)

  // Clamped during render rather than in an effect, so a frame that shrinks
  // (Phase 3.5 hex editing) cannot leave the roving focus past the end.
  const focusOffset = Math.min(requestedFocus, Math.max(0, frame.length - 1))

  useEffect(() => {
    if (!shouldFocus.current) return
    shouldFocus.current = false
    cells.current[focusOffset]?.focus()
  }, [focusOffset])

  const moveTo = useCallback(
    (offset: number) => {
      const next = Math.min(Math.max(0, offset), frame.length - 1)
      shouldFocus.current = true
      setFocusOffset(next)
    },
    [frame.length],
  )

  const selectAt = useCallback(
    (offset: number) => {
      const found = fieldAtOffset(packet, offset)
      selectField(found?.node.id ?? null, found?.occurrence ?? 0)
    },
    [packet, selectField],
  )

  const onKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLDivElement>) => {
      // Editing keys first, and they all return: navigation keeps the arrows,
      // which is the accessible path through the grid and worth more than the
      // hex-editor convention of nudging a value with them.
      if (onEditByte !== undefined) {
        if (/^[0-9a-fA-F]$/.test(event.key)) {
          event.preventDefault()
          const digit = Number.parseInt(event.key, 16)
          if (pending !== null && pending.offset === focusOffset) {
            onEditByte(focusOffset, pending.nibble * 16 + digit)
            setPending(null)
          } else {
            setPending({ offset: focusOffset, nibble: digit })
          }
          return
        }
        if (event.key === '+' || event.key === '-') {
          event.preventDefault()
          const current = frame[focusOffset]
          if (current !== undefined) {
            onEditByte(focusOffset, (current + (event.key === '+' ? 1 : 255)) % 256)
          }
          setPending(null)
          return
        }
        if (event.key === 'Escape') {
          event.preventDefault()
          setPending(null)
          return
        }
      }
      setPending(null)

      const keys: Record<string, number> = {
        ArrowRight: 1,
        ArrowLeft: -1,
        ArrowDown: BYTES_PER_ROW,
        ArrowUp: -BYTES_PER_ROW,
        PageDown: BYTES_PER_ROW * 4,
        PageUp: -BYTES_PER_ROW * 4,
      }
      const delta = keys[event.key]

      if (delta !== undefined) {
        event.preventDefault()
        moveTo(focusOffset + delta)
        return
      }
      if (event.key === 'Home') {
        event.preventDefault()
        moveTo(event.ctrlKey ? 0 : focusOffset - (focusOffset % BYTES_PER_ROW))
        return
      }
      if (event.key === 'End') {
        event.preventDefault()
        const rowEnd = focusOffset - (focusOffset % BYTES_PER_ROW) + BYTES_PER_ROW - 1
        moveTo(event.ctrlKey ? frame.length - 1 : rowEnd)
        return
      }
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault()
        selectAt(focusOffset)
      }
    },
    [focusOffset, frame, moveTo, onEditByte, pending, selectAt],
  )

  const rowCount = Math.max(1, Math.ceil(frame.length / BYTES_PER_ROW))
  const rows = Array.from({ length: rowCount }, (_unused, row) => row * BYTES_PER_ROW)

  return (
    <div className="hex">
      <ul className="hex-legend">
        {sections.map((section) => (
          <li key={section.id} className={`hex-legend-item is-sect-${section.index % 4}`}>
            {/* Deliberately not a control: the same selection is one click away
                in the field tree, and three extra tab stops in front of the hex
                grid would make the keyboard path to the bytes longer for no
                new capability. */}
            <span className="hex-legend-name">{section.name}</span>
            <span className="hex-legend-range">
              {section.byteStart}–{section.byteStart + section.byteLength - 1}
            </span>
          </li>
        ))}
      </ul>

      {onEditByte === undefined ? null : (
        <p className="hex-hint" id="hex-edit-hint">
          The bytes are writable: focus one and type two hex digits to rewrite it,
          <kbd>+</kbd> or <kbd>-</kbd> to nudge it by one, <kbd>Esc</kbd> to cancel a
          half-typed byte. Every edit rebuilds the packet from the new buffer.
        </p>
      )}

      <div className="hex-head">
        <span className="hex-offset" aria-hidden="true">
          offset
        </span>
        <span className="hex-columns" aria-hidden="true">
          {Array.from({ length: BYTES_PER_ROW }, (_unused, i) => (
            <span key={i} className="hex-col-label">
              {i.toString(16)}
            </span>
          ))}
        </span>
        <span className="hex-ascii-label" aria-hidden="true">
          ascii
        </span>
      </div>

      <div
        className="hex-grid"
        role="grid"
        aria-label={`Frame bytes, ${frame.length} total`}
        aria-describedby={
          onEditByte === undefined ? 'field-detail-panel' : 'field-detail-panel hex-edit-hint'
        }
        aria-rowcount={rowCount}
        aria-colcount={BYTES_PER_ROW}
        onKeyDown={onKeyDown}
        onMouseLeave={() => hoverField(null)}
      >
        {rows.map((rowStart, rowIndex) => (
          <div className="hex-row" role="row" aria-rowindex={rowIndex + 1} key={rowStart}>
            <span className="hex-offset" role="rowheader">
              {rowStart.toString(16).padStart(4, '0')}
            </span>

            <span className="hex-bytes">
              {Array.from({ length: BYTES_PER_ROW }, (_unused, column) => {
                const offset = rowStart + column
                const byte = frame[offset]
                if (byte === undefined) {
                  return <span className="hex-cell hex-empty" key={column} aria-hidden="true" />
                }
                const typing = pending !== null && pending.offset === offset
                const changed = baseline !== undefined && baseline[offset] !== byte
                return (
                  <div
                    key={column}
                    ref={(element) => {
                      cells.current[offset] = element
                    }}
                    role="gridcell"
                    aria-colindex={column + 1}
                    tabIndex={offset === focusOffset ? 0 : -1}
                    className={cellClass(offset, selected, hovered, packet.problems, sections, {
                      typing,
                      changed,
                    })}
                    aria-label={describeByte(offset, byte)}
                    aria-selected={inSpan(selected, offset)}
                    onClick={() => {
                      setFocusOffset(offset)
                      selectAt(offset)
                    }}
                    onFocus={() => setFocusOffset(offset)}
                    onMouseEnter={() => {
                      const found = fieldAtOffset(packet, offset)
                      hoverField(found?.node.id ?? null, found?.occurrence ?? 0)
                    }}
                  >
                    {typing ? `${pending.nibble.toString(16)}_` : byte.toString(16).padStart(2, '0')}
                  </div>
                )
              })}
            </span>

            <span className="hex-ascii">
              {Array.from({ length: BYTES_PER_ROW }, (_unused, column) => {
                const offset = rowStart + column
                const byte = frame[offset]
                if (byte === undefined) return <span key={column} className="hex-ascii-cell" />
                return (
                  <span
                    key={column}
                    className={`hex-ascii-cell${inSpan(selected, offset) ? ' is-selected' : ''}${
                      inSpan(hovered, offset) ? ' is-hovered' : ''
                    }`}
                    aria-hidden="true"
                  >
                    {byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : '.'}
                  </span>
                )
              })}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

function cellClass(
  offset: number,
  selected: Span | null,
  hovered: Span | null,
  problems: readonly Problem[],
  sections: readonly Section[],
  state: { typing: boolean; changed: boolean },
): string {
  const classes = ['hex-cell']
  const section = sectionAt(sections, offset)
  if (section !== undefined) classes.push(`is-sect-${section.index % 4}`)
  if (state.changed) classes.push('is-edited')
  if (state.typing) classes.push('is-typing')
  if (inSpan(selected, offset)) classes.push('is-selected')
  if (inSpan(hovered, offset)) classes.push('is-hovered')
  for (const problem of problems) {
    if (offset >= problem.byteStart && offset < problem.byteStart + problem.byteLength) {
      classes.push(problem.severity === 'error' ? 'is-error' : 'is-warning')
      break
    }
  }
  return classes.join(' ')
}

function describeByte(offset: number, byte: number): string {
  return `Byte ${offset}, value 0x${byte.toString(16).padStart(2, '0')}`
}
