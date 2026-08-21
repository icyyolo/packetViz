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

export type HexViewProps = {
  packet: DecodedPacket
}

export function HexView({ packet }: HexViewProps) {
  const { selectedFieldId, hoveredFieldId, selectField, hoverField } = useSelection()
  const frame = packet.frame
  const selected = spanOf(packet, selectedFieldId)
  const hovered = spanOf(packet, hoveredFieldId)

  const [requestedFocus, setFocusOffset] = useState(0)
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
      const node = fieldAtOffset(packet, offset)
      selectField(node?.id ?? null)
    },
    [packet, selectField],
  )

  const onKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLDivElement>) => {
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
    [focusOffset, frame.length, moveTo, selectAt],
  )

  const rowCount = Math.max(1, Math.ceil(frame.length / BYTES_PER_ROW))
  const rows = Array.from({ length: rowCount }, (_unused, row) => row * BYTES_PER_ROW)

  return (
    <div className="hex">
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
        aria-describedby="field-detail-panel"
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
                return (
                  <div
                    key={column}
                    ref={(element) => {
                      cells.current[offset] = element
                    }}
                    role="gridcell"
                    aria-colindex={column + 1}
                    tabIndex={offset === focusOffset ? 0 : -1}
                    className={cellClass(offset, selected, hovered, packet.problems)}
                    aria-label={describeByte(offset, byte)}
                    aria-selected={inSpan(selected, offset)}
                    onClick={() => {
                      setFocusOffset(offset)
                      selectAt(offset)
                    }}
                    onFocus={() => setFocusOffset(offset)}
                    onMouseEnter={() => hoverField(fieldAtOffset(packet, offset)?.id ?? null)}
                  >
                    {byte.toString(16).padStart(2, '0')}
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
): string {
  const classes = ['hex-cell']
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
