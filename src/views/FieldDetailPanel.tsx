/**
 * The explainer.
 *
 * Everything shown here comes from the `FieldSpec` table that also drives
 * decoding, so a field is described in exactly one place and cannot ship
 * unexplained (asserted by `tests/spec-coverage.test.ts`).
 *
 * Hover previews without stealing the selection, and the panel is wired to the
 * tree and hex grid through `aria-describedby` rather than being a hover-only
 * tooltip, so it works for keyboard and screen-reader users too.
 */

import { Link } from 'react-router-dom'
import type { DecodedPacket } from '../core/field.ts'
import { formatHexBytes } from '../core/format.ts'
import { findProtocol } from '../core/registry.ts'
import { nodeOf, useSelection } from './selection.ts'

export type FieldDetailPanelProps = {
  packet: DecodedPacket
}

export function FieldDetailPanel({ packet }: FieldDetailPanelProps) {
  const { selectedFieldId, hoveredFieldId } = useSelection()

  const selected = nodeOf(packet, selectedFieldId)
  const hovered = nodeOf(packet, hoveredFieldId)
  const node = hovered ?? selected
  const previewing = hovered !== undefined && hovered.id !== selected?.id

  return (
    <aside
      className="detail"
      id="field-detail-panel"
      aria-live="polite"
      aria-label="Field detail"
    >
      {node === undefined ? (
        <p className="detail-empty">
          Select a field in the tree, or a byte in the hex dump. They are the same thing seen from
          two sides.
        </p>
      ) : (
        <>
          <header className="detail-head">
            <h3 className="detail-name">{node.name}</h3>
            <code className="detail-id">{node.id}</code>
            {previewing ? <span className="detail-preview-tag">preview</span> : null}
          </header>

          <dl className="detail-facts">
            <div>
              <dt>Offset</dt>
              <dd>
                {node.byteStart}
                {node.byteLength > 1 ? `–${node.byteStart + node.byteLength - 1}` : ''}
              </dd>
            </div>
            <div>
              <dt>Size</dt>
              <dd>
                {node.bitLength !== undefined
                  ? `${node.bitLength} bit${node.bitLength === 1 ? '' : 's'} (bit ${node.bitOffset ?? 0} of byte ${node.byteStart})`
                  : `${node.byteLength} byte${node.byteLength === 1 ? '' : 's'}`}
              </dd>
            </div>
            <div>
              <dt>Value</dt>
              <dd className="detail-value">{node.value}</dd>
            </div>
            {node.valueName !== undefined ? (
              <div>
                <dt>Means</dt>
                <dd>{node.valueName}</dd>
              </div>
            ) : null}
            <div>
              <dt>Raw</dt>
              <dd className="detail-raw">{formatHexBytes(node.raw.subarray(0, 16))}</dd>
            </div>
          </dl>

          {node.description !== undefined ? (
            <p className="detail-description">{node.description}</p>
          ) : null}

          {node.reference !== undefined ? (
            <p className="detail-reference">{node.reference}</p>
          ) : null}

          {/* The wire format behind this one packet. The protocol is the field
              id's own prefix, so nothing here needs a table of its own. */}
          {referenceLink(node.id)}
        </>
      )}
    </aside>
  )
}

/**
 * A link to the field's row on the generated reference page, when the field
 * belongs to a protocol that has one. Option fields (`dhcp.opt.53.value`) land
 * on the DHCP page, which carries the option dictionary they come from.
 */
function referenceLink(fieldId: string) {
  const protocolId = fieldId.split('.')[0] ?? ''
  const protocol = findProtocol(protocolId)
  if (protocol === undefined || !protocol.implemented) return null

  return (
    <p className="detail-reference-link">
      <Link to={`/reference/${protocol.id}?f=${fieldId}`}>
        {protocol.name} header reference
      </Link>
    </p>
  )
}
