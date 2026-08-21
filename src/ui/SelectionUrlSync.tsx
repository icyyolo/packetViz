/**
 * Mirrors the selection into the query string so any field of any packet is a
 * shareable link.
 *
 * Writes with `replace`, not `push`: the back button should leave the lesson,
 * not unwind a hundred clicks inside it.
 */

import { useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useSelection } from '../views/selection.ts'

export function SelectionUrlSync() {
  const { packetIndex, selectedFieldId } = useSelection()
  const [, setSearchParams] = useSearchParams()

  useEffect(() => {
    setSearchParams(
      (current) => {
        const next = new URLSearchParams(current)
        next.set('p', String(packetIndex))
        if (selectedFieldId === null) next.delete('f')
        else next.set('f', selectedFieldId)
        return next
      },
      { replace: true },
    )
  }, [packetIndex, selectedFieldId, setSearchParams])

  return null
}
