/**
 * Layer 1: the segment.
 *
 * A static scene, deliberately not a simulator. For one L2 segment with three
 * hosts there is nothing to simulate: `linkDelayMs` is a scene constant and the
 * packet dot's position is `f(t)`, with no loss model, queueing or congestion.
 *
 * The dot's label is the decode's own summary.
 */

import { flightProgress, type CompiledTimeline } from '../scenario/compile.ts'
import { useSelection } from './selection.ts'

export type TopologyViewProps = {
  timeline: CompiledTimeline
  tMs: number
}

const WIDTH = 720
const HEIGHT = 200
const BUS_Y = 150
const HOST_Y = 44
const HOST_W = 132
const HOST_H = 56

export function TopologyView({ timeline, tMs }: TopologyViewProps) {
  const { selectPacket } = useSelection()
  const hosts = timeline.hosts
  const columnWidth = WIDTH / hosts.length
  const xOf = (hostId: string): number => {
    const index = hosts.findIndex((host) => host.id === hostId)
    return columnWidth * (index < 0 ? 0 : index) + columnWidth / 2
  }

  const inFlight = timeline.marks.flatMap((mark) => {
    const progress = flightProgress(mark, tMs)
    if (progress === null) return []
    const targets = mark.to === null ? hosts.filter((h) => h.id !== mark.from) : hosts.filter((h) => h.id === mark.to)
    return targets.map((target) => ({
      key: `${mark.packetIndex}-${target.id}`,
      packetIndex: mark.packetIndex,
      x: xOf(mark.from) + (xOf(target.id) - xOf(mark.from)) * progress,
    }))
  })

  return (
    <svg
      className="topology"
      viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
      role="img"
      aria-label="Network topology"
    >
      <line className="topo-bus" x1={20} y1={BUS_Y} x2={WIDTH - 20} y2={BUS_Y} />
      <text className="topo-bus-label" x={WIDTH - 20} y={BUS_Y + 20} textAnchor="end">
        Ethernet segment · {timeline.linkDelayMs} ms
      </text>

      {hosts.map((host) => (
        <g className="topo-host" key={host.id}>
          <line x1={xOf(host.id)} y1={HOST_Y + HOST_H} x2={xOf(host.id)} y2={BUS_Y} />
          <rect
            x={xOf(host.id) - HOST_W / 2}
            y={HOST_Y}
            width={HOST_W}
            height={HOST_H}
            rx={6}
          />
          <text x={xOf(host.id)} y={HOST_Y + 20} textAnchor="middle" className="topo-host-label">
            {host.label}
          </text>
          <text x={xOf(host.id)} y={HOST_Y + 36} textAnchor="middle" className="topo-host-addr">
            {host.ip}
          </text>
          <text x={xOf(host.id)} y={HOST_Y + 49} textAnchor="middle" className="topo-host-addr">
            {host.mac}
          </text>
        </g>
      ))}

      {inFlight.map((dot) => (
        <circle
          key={dot.key}
          className="topo-packet"
          cx={dot.x}
          cy={BUS_Y}
          r={7}
          onClick={() => selectPacket(dot.packetIndex)}
        />
      ))}
    </svg>
  )
}
