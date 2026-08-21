/**
 * Timeline glue for the neighbour caches.
 *
 * Kept out of the components so the ladder and the cache table fold the same
 * deliveries exactly once and cannot disagree about who learned what.
 */

import { useMemo } from 'react'
import { foldArpCaches, type CacheSnapshot, type Delivery } from '../core/arp-cache.ts'
import { arpMessage } from '../core/protocols/arp.ts'
import type { CompiledTimeline } from '../scenario/compile.ts'

export function useArpCaches(timeline: CompiledTimeline): CacheSnapshot[] {
  return useMemo(() => {
    const deliveries: Delivery[] = []
    for (const mark of timeline.marks) {
      const packet = timeline.packets[mark.packetIndex]
      if (packet === undefined) continue
      const message = arpMessage(packet)
      if (message === undefined) continue
      deliveries.push({ packetIndex: mark.packetIndex, arrivedMs: mark.arrivedMs, message })
    }
    return foldArpCaches(timeline.hosts, deliveries)
  }, [timeline])
}
