import { useCallback, useMemo, useState, type ReactNode } from 'react'
import { SelectionContext, type SelectionApi } from './selection.ts'

export type SelectionProviderProps = {
  packetCount: number
  initialPacketIndex?: number
  initialFieldId?: string | null
  children: ReactNode
}

export function SelectionProvider(props: SelectionProviderProps) {
  const { packetCount, initialPacketIndex = 0, initialFieldId = null, children } = props

  const [packetIndex, setPacketIndex] = useState(() =>
    clampIndex(initialPacketIndex, packetCount),
  )
  const [selectedFieldId, setSelectedFieldId] = useState<string | null>(initialFieldId)
  const [hoveredFieldId, setHoveredFieldId] = useState<string | null>(null)

  const selectPacket = useCallback(
    (index: number) => {
      // Field ids are shared across packets of the same protocol, so the
      // selected field carries over instead of being dropped on packet change.
      setPacketIndex(clampIndex(index, packetCount))
    },
    [packetCount],
  )

  const value = useMemo<SelectionApi>(
    () => ({
      packetIndex,
      selectedFieldId,
      hoveredFieldId,
      selectPacket,
      selectField: setSelectedFieldId,
      hoverField: setHoveredFieldId,
    }),
    [packetIndex, selectedFieldId, hoveredFieldId, selectPacket],
  )

  return <SelectionContext.Provider value={value}>{children}</SelectionContext.Provider>
}

function clampIndex(index: number, count: number): number {
  return Math.min(Math.max(0, index), Math.max(0, count - 1))
}
