/**
 * Scenario -> CompiledTimeline.
 *
 * Calls `build()` once per event and `decodeFrame()` once per frame. Everything
 * downstream — all four views, the detail panel, the export — reads the decode,
 * never the scenario.
 */

import type { DecodedPacket } from '../core/field.ts'
import { decodeFrame } from '../core/registry.ts'
import type { Host, Scenario } from './types.ts'

export type TimelineMark = {
  packetIndex: number
  /** Transmission time. */
  sentMs: number
  /** `sentMs + linkDelayMs`. */
  arrivedMs: number
  from: string
  to: string | null
}

export type CompiledTimeline = {
  hosts: Host[]
  linkDelayMs: number
  packets: DecodedPacket[]
  marks: TimelineMark[]
  /** Total scrubbable length: last arrival plus a short tail so it can be watched. */
  durationMs: number
}

const TAIL_MS = 400

export function compileScenario(scenario: Scenario): CompiledTimeline {
  const packets: DecodedPacket[] = []
  const marks: TimelineMark[] = []

  scenario.events.forEach((event, packetIndex) => {
    packets.push(decodeFrame(event.build()))
    marks.push({
      packetIndex,
      sentMs: event.tMs,
      arrivedMs: event.tMs + scenario.linkDelayMs,
      from: event.from,
      to: event.to,
    })
  })

  const lastArrival = marks.reduce((max, mark) => Math.max(max, mark.arrivedMs), 0)

  return {
    hosts: scenario.hosts,
    linkDelayMs: scenario.linkDelayMs,
    packets,
    marks,
    durationMs: lastArrival + TAIL_MS,
  }
}

/** Index of the most recent packet to have been sent at time `tMs`, or -1. */
export function markAt(marks: readonly TimelineMark[], tMs: number): number {
  let index = -1
  for (const mark of marks) {
    if (mark.sentMs <= tMs) index = mark.packetIndex
  }
  return index
}

/**
 * Position of a packet along the wire at time `tMs`, as a fraction in [0, 1],
 * or `null` when it is not in flight. Pure `f(t)`.
 */
export function flightProgress(mark: TimelineMark, tMs: number): number | null {
  if (tMs < mark.sentMs || tMs > mark.arrivedMs) return null
  const span = mark.arrivedMs - mark.sentMs
  if (span <= 0) return 1
  return (tMs - mark.sentMs) / span
}
