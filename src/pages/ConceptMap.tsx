/**
 * The encapsulation stack, drawn from the protocol registry.
 *
 * Nesting is the point: a DHCP message is inside a UDP datagram is inside an
 * IPv4 packet is inside an Ethernet frame, and the boxes are nested the same way
 * the bytes are. Everything here — which blocks exist, which contain which, and
 * which are greyed out — comes from `describeProtocols()`, so the map cannot
 * advertise a protocol that has no decoder. Unregister one and its block greys
 * out with no edit to this file (`tests/registry.test.ts` proves it).
 *
 * Nested elements rather than an SVG drawing, which is a deliberate departure
 * from the plan: real buttons are keyboard-reachable and screen-reader-legible
 * for free, text wraps instead of overflowing, and the whole thing reflows on a
 * phone. An SVG would have needed all three re-implemented by hand.
 */

import type { ReactElement } from 'react'
import { describeProtocols, type ProtocolDescription } from '../core/registry.ts'

export type ConceptMapProps = {
  /** Protocol id whose lessons are currently highlighted, if any. */
  selected: string | null
  onSelect: (id: string | null) => void
}

export function ConceptMap({ selected, onSelect }: ConceptMapProps) {
  const protocols = describeProtocols()
  const byId = new Map(protocols.map((protocol) => [protocol.id, protocol]))
  const root = byId.get('eth')

  if (root === undefined) return null

  const render = (protocol: ProtocolDescription): ReactElement => (
    <div
      key={protocol.id}
      className={`map-block${protocol.implemented ? '' : ' is-todo'}${
        selected === protocol.id ? ' is-selected' : ''
      }`}
    >
      <button
        type="button"
        className="map-label"
        aria-pressed={protocol.implemented ? selected === protocol.id : undefined}
        disabled={!protocol.implemented}
        title={protocol.blurb}
        onClick={() => onSelect(selected === protocol.id ? null : protocol.id)}
      >
        <span className="map-name">{protocol.name}</span>
        <span className="map-layer">L{protocol.layer}</span>
        {protocol.implemented ? null : <span className="map-todo">not implemented</span>}
      </button>

      {protocol.encapsulates.length === 0 ? null : (
        <div className="map-children">
          {protocol.encapsulates.map((id) => {
            const child = byId.get(id)
            return child === undefined ? null : render(child)
          })}
        </div>
      )}
    </div>
  )

  return (
    <section className="map" aria-label="Protocol stack">
      <div className="map-head">
        <h2>What is implemented</h2>
        <p className="map-note">
          Each box is a protocol carried by the one around it. Solid blocks have a decoder and can
          be clicked to find the lessons that put them on the wire; greyed blocks are named so the
          edges of this project are visible, not hidden.
        </p>
      </div>
      {render(root)}
      {selected === null ? null : (
        <button type="button" className="map-clear" onClick={() => onSelect(null)}>
          Clear filter
        </button>
      )}
    </section>
  )
}
