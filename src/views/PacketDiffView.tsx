/**
 * Two packets, field by field, with everything identical thrown away.
 *
 * ARP's clearest teaching moment is the swap: request and reply carry the same
 * 28-byte layout, and going from one to the other changes six fields and nothing
 * else. Reading that off two separate hex dumps is work; reading it off one
 * table is not.
 *
 * Rows are matched by field id, so this is not ARP-specific — any two decodes of
 * the same shape diff the same way. Rows are selectable, so a difference can be
 * chased straight back into the bytes.
 */

import { leafFields, type DecodedPacket } from '../core/field.ts'
import { useSelection } from './selection.ts'

export type PacketDiffViewProps = {
  left: DecodedPacket
  leftIndex: number
  right: DecodedPacket
  rightIndex: number
}

type DiffRow = {
  id: string
  name: string
  leftValue: string | undefined
  rightValue: string | undefined
}

export function PacketDiffView(props: PacketDiffViewProps) {
  const { left, leftIndex, right, rightIndex } = props
  const { selectedFieldId, selectField, hoverField } = useSelection()
  const rows = diffPackets(left, right)

  if (rows.length === 0) {
    return <p className="diff-same">These two packets decode to identical field values.</p>
  }

  return (
    <table className="diff-table">
      <caption>
        {rows.length} field{rows.length === 1 ? '' : 's'} differ. Everything else is byte-identical.
      </caption>
      <thead>
        <tr>
          <th scope="col">Field</th>
          <th scope="col">Packet #{leftIndex + 1}</th>
          <th scope="col">Packet #{rightIndex + 1}</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => (
          <tr
            key={row.id}
            className={row.id === selectedFieldId ? 'is-selected' : ''}
            onMouseEnter={() => hoverField(row.id)}
            onMouseLeave={() => hoverField(null)}
          >
            <th scope="row">
              <button type="button" className="diff-field" onClick={() => selectField(row.id)}>
                {row.name}
              </button>
            </th>
            <td className="diff-value">{row.leftValue ?? <em>absent</em>}</td>
            <td className="diff-value is-changed">{row.rightValue ?? <em>absent</em>}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

/** Leaf fields present in either packet whose rendered values disagree. */
function diffPackets(left: DecodedPacket, right: DecodedPacket): DiffRow[] {
  const leftLeaves = new Map([...leafFields(left.tree)].map((node) => [node.id, node]))
  const rightLeaves = new Map([...leafFields(right.tree)].map((node) => [node.id, node]))
  const ids = [...new Set([...leftLeaves.keys(), ...rightLeaves.keys()])]

  const rows: DiffRow[] = []
  for (const id of ids) {
    const a = leftLeaves.get(id)
    const b = rightLeaves.get(id)
    if (a?.value === b?.value) continue
    rows.push({
      id,
      name: a?.name ?? b?.name ?? id,
      leftValue: a?.value,
      rightValue: b?.value,
    })
  }
  return rows
}
