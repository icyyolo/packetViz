/**
 * Layer 4 is writable, and this is where the write lands.
 *
 * The invariant the whole project rests on is that a packet is one byte buffer
 * and every layer is a projection of it. Editing is the demonstration: a
 * keystroke produces a NEW `Uint8Array` — nothing is mutated in place, and no
 * decoded value is patched — the frame is decoded again from scratch, and all
 * four layers move because they never had their own copy of anything.
 *
 * The scenario's own buffers are never touched, so Reset is just "forget the
 * override" rather than an undo log.
 */

import { useCallback, useMemo, useState } from 'react'
import { decodeFrame } from '../core/registry.ts'
import type { CompiledTimeline } from '../scenario/compile.ts'

export type EditableTimeline = {
  /** The base timeline with every edited packet re-decoded from its new bytes. */
  timeline: CompiledTimeline
  /** Packet indexes whose bytes now differ from the scenario's. */
  edited: ReadonlySet<number>
  setByte: (packetIndex: number, offset: number, value: number) => void
  reset: (packetIndex: number) => void
}

export function useEditableTimeline(base: CompiledTimeline): EditableTimeline {
  const [overrides, setOverrides] = useState<ReadonlyMap<number, Uint8Array>>(new Map())

  const setByte = useCallback(
    (packetIndex: number, offset: number, value: number): void => {
      setOverrides((previous) => {
        const current = previous.get(packetIndex) ?? base.packets[packetIndex]?.frame
        if (current === undefined || offset < 0 || offset >= current.length) return previous

        // A new buffer every time. Mutating `current` would leave React's state
        // identity unchanged and, worse, would edit the scenario's own bytes.
        const next = Uint8Array.from(current)
        next[offset] = value & 0xff

        const map = new Map(previous)
        map.set(packetIndex, next)
        return map
      })
    },
    [base],
  )

  const reset = useCallback((packetIndex: number): void => {
    setOverrides((previous) => {
      if (!previous.has(packetIndex)) return previous
      const map = new Map(previous)
      map.delete(packetIndex)
      return map
    })
  }, [])

  const timeline = useMemo((): CompiledTimeline => {
    if (overrides.size === 0) return base
    return {
      ...base,
      packets: base.packets.map((packet, index) => {
        const frame = overrides.get(index)
        return frame === undefined ? packet : decodeFrame(frame)
      }),
    }
  }, [base, overrides])

  // Derived by comparison rather than by "an override exists", so typing a byte
  // back to its original value clears the badge instead of lying about it.
  const edited = useMemo((): ReadonlySet<number> => {
    const set = new Set<number>()
    for (const [index, frame] of overrides) {
      const original = base.packets[index]?.frame
      if (original !== undefined && !sameBytes(frame, original)) set.add(index)
    }
    return set
  }, [base, overrides])

  return { timeline, edited, setByte, reset }
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  return a.every((byte, index) => byte === b[index])
}
