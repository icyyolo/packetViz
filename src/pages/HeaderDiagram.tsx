/**
 * The RFC-style header diagram. Layout comes from `diagram.ts`; this only draws
 * the boxes, sized by `flex-grow` so a 6-bit field is visibly narrower than a
 * 16-bit one at any screen width.
 */

import { ROW_BITS, diagramRows } from './diagram.ts'
import type { FieldSpec } from '../core/spec.ts'

export type HeaderDiagramProps = {
  specs: readonly FieldSpec[]
  /** Field id to mark as current, e.g. the one the reader followed a link to. */
  highlighted?: string | null
  onSelect?: (fieldId: string) => void
}

export function HeaderDiagram({ specs, highlighted, onSelect }: HeaderDiagramProps) {
  const rows = diagramRows(specs)
  if (rows.length === 0) return null

  return (
    <div className="diagram" role="img" aria-label="Header layout, 32 bits per row">
      <div className="diagram-ruler" aria-hidden="true">
        {[0, 8, 16, 24].map((bit) => (
          <span className="diagram-tick" key={bit}>
            {bit}
          </span>
        ))}
      </div>

      {rows.map((row) => (
        <div className="diagram-row" key={row.bitStart}>
          {row.cells.map((cell, index) => (
            <button
              key={`${cell.spec.id}-${index}`}
              type="button"
              className={`diagram-cell${cell.elided ? ' is-elided' : ''}${
                highlighted === cell.spec.id ? ' is-highlighted' : ''
              }`}
              style={{ flexGrow: cell.elided ? ROW_BITS : cell.bits }}
              title={`${cell.spec.name} — ${cell.spec.bits} bits`}
              onClick={() => onSelect?.(cell.spec.id)}
            >
              <span className="diagram-name">
                {cell.first ? cell.spec.name : `${cell.spec.name} (cont.)`}
              </span>
              <span className="diagram-bits">
                {cell.elided ? `${cell.spec.bits / 8} bytes` : `${cell.bits} b`}
              </span>
            </button>
          ))}
        </div>
      ))}
    </div>
  )
}
