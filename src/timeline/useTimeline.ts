import { useCallback, useEffect, useState, useSyncExternalStore } from 'react'
import { VirtualClock, type ClockSnapshot } from './clock.ts'

/** A clock whose lifetime follows the component, kept in step with the scenario length. */
export function useVirtualClock(durationMs: number): VirtualClock {
  const [clock] = useState(() => new VirtualClock(durationMs))

  useEffect(() => {
    clock.setDuration(durationMs)
  }, [clock, durationMs])

  useEffect(() => () => clock.dispose(), [clock])

  return clock
}

export function useClockSnapshot(clock: VirtualClock): ClockSnapshot {
  const subscribe = useCallback((listener: () => void) => clock.subscribe(listener), [clock])
  const snapshot = useCallback(() => clock.getSnapshot(), [clock])
  return useSyncExternalStore(subscribe, snapshot, snapshot)
}
