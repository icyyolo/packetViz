/**
 * The generic companion to layers 3 and 4.
 *
 * "Decoded fields" and "Bytes on the wire" answer *what this packet says*. This
 * table answers *what an ARP packet is* — every field of every header in the
 * stack, with its offset, width, meaning, RFC reference and value dictionary,
 * whether or not the packet in front of you exercises it.
 *
 * Both tables are generated from the same `FieldSpec` arrays the decoder runs,
 * so they cannot drift apart: `tests/layout.test.ts` asserts every row's offset
 * equals the decoded field's `byteStart` for the same id.
 *
 * Rows are selectable, which is the point of showing it here rather than on a
 * separate reference page: click "Opcode" in the layout and the packet's own
 * bytes light up in hex.
 */

import type { DecodedPacket } from '../core/field.ts'
import { ETH_MIN_FRAME_BYTES } from '../core/protocols/ethernet.ts'
import { frameLayout } from '../core/registry.ts'
import type { SpecRow } from '../core/spec.ts'
import { useSelection } from './selection.ts'

export type LayoutViewProps = {
  packet: DecodedPacket
}

export function LayoutView({ packet }: LayoutViewProps) {
  const sections = frameLayout(packet)
  const { selectedFieldId, selectField, hoverField } = useSelection()

  return (
    <div className="layout">
      {sections.map((section) => (
        <table className="layout-table" key={section.id}>
          <caption>
            {section.name} — {section.byteLength} bytes
          </caption>
          <thead>
            <tr>
              <th scope="col">Offset</th>
              <th scope="col">Size</th>
              <th scope="col">Field</th>
              <th scope="col">Meaning</th>
            </tr>
          </thead>
          <tbody>
            {section.rows.map((row) => (
              <tr
                key={row.spec.id}
                className={row.spec.id === selectedFieldId ? 'is-selected' : ''}
                onMouseEnter={() => hoverField(row.spec.id)}
                onMouseLeave={() => hoverField(null)}
              >
                <td className="layout-offset">{offsetLabel(row)}</td>
                <td className="layout-size">{sizeLabel(row.spec.bits)}</td>
                <td>
                  <button
                    type="button"
                    className="layout-field"
                    onClick={() => selectField(row.spec.id)}
                  >
                    {row.spec.name}
                  </button>
                  <span className="layout-id">{row.spec.id}</span>
                </td>
                <td>
                  <p className="layout-desc">{row.spec.description}</p>
                  {row.spec.values === undefined ? null : (
                    <ul className="layout-values">
                      {Object.entries(row.spec.values).map(([value, name]) => (
                        <li key={value}>
                          <code>{value}</code> {name}
                        </li>
                      ))}
                    </ul>
                  )}
                  {row.spec.reference === undefined ? null : (
                    <p className="layout-ref">{row.spec.reference}</p>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ))}
      <p className="layout-note">
        Offsets are absolute within the frame, so they are the same numbers the hex view
        shows. Ethernet padding to the {ETH_MIN_FRAME_BYTES}-byte minimum is not part of any header and so
        has no row here; it appears in the decode when a frame is short.
      </p>
    </div>
  )
}

function offsetLabel(row: SpecRow): string {
  if (row.spec.bits % 8 === 0 && row.bitOffset === 0) return String(row.byteStart)
  return `${row.byteStart}.${row.bitOffset}`
}

function sizeLabel(bits: number): string {
  if (bits % 8 !== 0) return `${bits} bit${bits === 1 ? '' : 's'}`
  const bytes = bits / 8
  return `${bytes} byte${bytes === 1 ? '' : 's'}`
}
