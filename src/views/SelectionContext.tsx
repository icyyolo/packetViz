import { useCallback, useMemo, useState, type ReactNode } from 'react'
import { SelectionContext, type SelectionApi, type SelectionState } from './selection.ts'

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
  const [selected, setSelected] = useState<Pick<SelectionState, 'selectedFieldId' | 'selectedOccurrence'>>(
    () => ({ selectedFieldId: initialFieldId, selectedOccurrence: 0 }),
  )
  const [hovered, setHovered] = useState<Pick<SelectionState, 'hoveredFieldId' | 'hoveredOccurrence'>>(
    () => ({ hoveredFieldId: null, hoveredOccurrence: 0 }),
  )

  // An id and its occurrence always move together: setting one without the
  // other is how the third No-Operation option ends up highlighting the first.
  const selectField = useCallback((fieldId: string | null, occurrence = 0) => {
    setSelected({ selectedFieldId: fieldId, selectedOccurrence: occurrence })
  }, [])

  const hoverField = useCallback((fieldId: string | null, occurrence = 0) => {
    setHovered({ hoveredFieldId: fieldId, hoveredOccurrence: occurrence })
  }, [])

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
      ...selected,
      ...hovered,
      selectPacket,
      selectField,
      hoverField,
    }),
    [packetIndex, selected, hovered, selectPacket, selectField, hoverField],
  )

  return <SelectionContext.Provider value={value}>{children}</SelectionContext.Provider>
}

function clampIndex(index: number, count: number): number {
  return Math.min(Math.max(0, index), Math.max(0, count - 1))
}
