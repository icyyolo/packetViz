/**
 * Layer 2: the ladder diagram.
 *
 * One lifeline per host, one arrow per transmission, drawn from send time to
 * arrival time so the slope IS the propagation delay. The playhead is a pure
 * function of `t`; arrows that have not been sent yet are dimmed rather than
 * hidden, so the shape of the exchange is legible while paused at t=0.
 *
 * Every arrow label comes from `DecodedPacket.summary` — the decode, not the
 * scenario.
 */

import { outcomesOf, type CacheSnapshot, type Reception } from '../core/arp-cache.ts'
import type { DecodedPacket } from '../core/field.ts'
import type { CompiledTimeline } from '../scenario/compile.ts'
import { useSelection } from './selection.ts'

export type FlowViewProps = {
  timeline: CompiledTimeline
  snapshots: CacheSnapshot[]
  tMs: number
}

/**
 * What a receiving host did with the frame, in the fewest words that stay true.
 * `sent` never renders — the sender is the tail of the arrow, not a target.
 */
const OUTCOME_LABEL: Record<Reception, string> = {
  sent: '',
  'not-addressed': 'NIC drops it',
  ignored: 'not for me',
  learned: 'caches sender',
  refreshed: 'refreshes entry',
  overwritten: 'entry overwritten',
  answered: 'that is me — replies',
}

/** Outcomes where the frame never reached the ARP layer, or was discarded by it. */
const DROPPED: ReadonlySet<Reception> = new Set<Reception>(['not-addressed', 'ignored'])

const WIDTH = 720
const HEAD_HEIGHT = 44
const PLOT_HEIGHT = 260
const BOTTOM_PAD = 16
const LABEL_LIFT = 8
const LABEL_MARGIN = 6
/** Approximate advance width of the 11px monospace label face. */
const LABEL_CHAR_WIDTH = 6.4

const clamp = (value: number, low: number, high: number): number =>
  low > high ? (low + high) / 2 : Math.min(Math.max(value, low), high)

export function FlowView({ timeline, snapshots, tMs }: FlowViewProps) {
  const { packetIndex, selectPacket, selectField } = useSelection()
  const hosts = timeline.hosts
  const columnWidth = WIDTH / (hosts.length + 1)
  const xOf = (hostId: string): number => {
    const index = hosts.findIndex((host) => host.id === hostId)
    return columnWidth * (index < 0 ? 0 : index + 1)
  }
  const yOf = (ms: number): number =>
    HEAD_HEIGHT + (timeline.durationMs === 0 ? 0 : (ms / timeline.durationMs) * PLOT_HEIGHT)

  const height = HEAD_HEIGHT + PLOT_HEIGHT + BOTTOM_PAD

  return (
    <svg
      className="flow"
      viewBox={`0 0 ${WIDTH} ${height}`}
      role="img"
      aria-label="Message ladder diagram"
    >
      <defs>
        <marker
          id="flow-arrow"
          viewBox="0 0 10 10"
          refX="9"
          refY="5"
          markerWidth="7"
          markerHeight="7"
          orient="auto-start-reverse"
        >
          <path d="M 0 0 L 10 5 L 0 10 z" fill="currentColor" />
        </marker>
      </defs>

      {hosts.map((host) => (
        <g key={host.id} className="flow-lifeline">
          <text x={xOf(host.id)} y={18} textAnchor="middle" className="flow-host">
            {host.label}
          </text>
          <text x={xOf(host.id)} y={32} textAnchor="middle" className="flow-host-addr">
            {host.ip}
          </text>
          <line
            x1={xOf(host.id)}
            y1={HEAD_HEIGHT}
            x2={xOf(host.id)}
            y2={HEAD_HEIGHT + PLOT_HEIGHT}
          />
        </g>
      ))}

      {timeline.marks.map((mark) => {
        const packet: DecodedPacket | undefined = timeline.packets[mark.packetIndex]
        // Every other host on the segment physically receives every frame; what
        // separates broadcast from unicast is what they DO with it, which is
        // read out of the bytes rather than from the scenario's `to` field.
        const targets = hosts.filter((host) => host.id !== mark.from)
        const outcomes = outcomesOf(snapshots, mark.packetIndex)
        const sent = mark.sentMs <= tMs
        const isSelected = mark.packetIndex === packetIndex

        // The label rides the arrow it describes rather than sitting at a fixed
        // x, which used to drop it straight on top of the middle lifeline. It
        // takes the midpoint of the first target's line, lifts clear of it, and
        // is clamped so a long summary cannot run off the viewBox. Arrows that
        // cross it are handled by the halo in `.flow-label` (paint-order:
        // stroke), not by moving anything.
        const label = packet?.summary ?? ''
        const primary = targets[0]
        const halfWidth = (label.length * LABEL_CHAR_WIDTH) / 2
        const labelX = clamp(
          (xOf(mark.from) + xOf(primary?.id ?? mark.from)) / 2,
          halfWidth + LABEL_MARGIN,
          WIDTH - halfWidth - LABEL_MARGIN,
        )
        const labelY = (yOf(mark.sentMs) + yOf(mark.arrivedMs)) / 2 - LABEL_LIFT

        return (
          <g
            key={mark.packetIndex}
            className={`flow-arrow${sent ? ' is-sent' : ''}${isSelected ? ' is-selected' : ''}`}
            onClick={() => {
              selectPacket(mark.packetIndex)
              selectField(null)
            }}
            role="button"
            tabIndex={0}
            aria-label={`Packet ${mark.packetIndex + 1}: ${packet?.summary ?? ''}`}
            onKeyDown={(event) => {
              if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault()
                selectPacket(mark.packetIndex)
                selectField(null)
              }
            }}
          >
            {targets.map((target) => {
              const outcome = outcomes.get(target.id) ?? 'ignored'
              const dropped = DROPPED.has(outcome)
              const toX = xOf(target.id)
              return (
                <g key={target.id} className={dropped ? 'is-dropped' : 'is-accepted'}>
                  <line
                    x1={xOf(mark.from)}
                    y1={yOf(mark.sentMs)}
                    x2={toX}
                    y2={yOf(mark.arrivedMs)}
                    markerEnd={dropped ? undefined : 'url(#flow-arrow)'}
                  />
                  {isSelected ? (
                    <text
                      className="flow-outcome"
                      x={toX + (toX < xOf(mark.from) ? -6 : 6)}
                      y={yOf(mark.arrivedMs) + 12}
                      textAnchor={toX < xOf(mark.from) ? 'end' : 'start'}
                    >
                      {OUTCOME_LABEL[outcome]}
                    </text>
                  ) : null}
                </g>
              )
            })}
            <text
              x={labelX}
              y={labelY}
              textAnchor="middle"
              className="flow-label"
            >
              {label}
            </text>
          </g>
        )
      })}

      <g className="flow-playhead">
        <line x1={0} y1={yOf(tMs)} x2={WIDTH} y2={yOf(tMs)} />
        <text x={4} y={yOf(tMs) - 4}>
          {tMs.toFixed(0)} ms
        </text>
      </g>
    </svg>
  )
}
