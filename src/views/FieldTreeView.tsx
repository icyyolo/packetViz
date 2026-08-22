/**
 * Layer 3: the decoded field tree.
 *
 * Every node here came out of `decode()`. Nothing is read from a lesson file,
 * which is why this directory may not import `src/lessons` at all — the lint
 * rule in `.oxlintrc.json` makes that a build failure rather than a convention.
 *
 * Accessibility: an ARIA `tree` with roving tabindex. Up/Down walk the visible
 * rows, Right expands (or steps into), Left collapses (or steps out), Enter or
 * Space selects.
 */

import { useCallback, useMemo, useRef, useState } from 'react'
import type { DecodedPacket, FieldNode } from '../core/field.ts'
import { useSelection } from './selection.ts'

export type FieldTreeViewProps = {
  packet: DecodedPacket
}

type Row = {
  node: FieldNode
  level: number
  hasChildren: boolean
  expanded: boolean
  parentId: string | null
}

export function FieldTreeView({ packet }: FieldTreeViewProps) {
  const { selectedFieldId, hoveredFieldId, selectField, hoverField } = useSelection()
  const [collapsed, setCollapsed] = useState<ReadonlySet<string>>(() => new Set())
  const [requestedFocus, setRequestedFocus] = useState(0)
  const items = useRef<(HTMLLIElement | null)[]>([])
  const shouldFocus = useRef(false)

  const rows = useMemo(() => flatten(packet.tree, collapsed), [packet, collapsed])
  const focusIndex = Math.min(requestedFocus, Math.max(0, rows.length - 1))

  const moveTo = useCallback((index: number) => {
    shouldFocus.current = true
    setRequestedFocus(index)
  }, [])

  const applyFocus = useCallback((index: number) => {
    if (!shouldFocus.current) return
    shouldFocus.current = false
    items.current[index]?.focus()
  }, [])

  const toggle = useCallback((id: string, expand: boolean) => {
    setCollapsed((current) => {
      const next = new Set(current)
      if (expand) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  const onKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLUListElement>) => {
      const row = rows[focusIndex]
      if (row === undefined) return

      switch (event.key) {
        case 'ArrowDown':
          event.preventDefault()
          moveTo(Math.min(focusIndex + 1, rows.length - 1))
          break
        case 'ArrowUp':
          event.preventDefault()
          moveTo(Math.max(focusIndex - 1, 0))
          break
        case 'ArrowRight':
          event.preventDefault()
          if (row.hasChildren && !row.expanded) toggle(row.node.id, true)
          else if (row.hasChildren) moveTo(Math.min(focusIndex + 1, rows.length - 1))
          break
        case 'ArrowLeft': {
          event.preventDefault()
          if (row.hasChildren && row.expanded) {
            toggle(row.node.id, false)
            break
          }
          const parent = rows.findIndex((candidate) => candidate.node.id === row.parentId)
          if (parent >= 0) moveTo(parent)
          break
        }
        case 'Home':
          event.preventDefault()
          moveTo(0)
          break
        case 'End':
          event.preventDefault()
          moveTo(rows.length - 1)
          break
        case 'Enter':
        case ' ':
          event.preventDefault()
          selectField(row.node.id)
          break
        default:
          break
      }
    },
    [focusIndex, moveTo, rows, selectField, toggle],
  )

  return (
    <ul
      className="tree"
      role="tree"
      aria-label="Decoded fields"
      onKeyDown={onKeyDown}
      onMouseLeave={() => hoverField(null)}
    >
      {/* `data-field-id` is a stable handle for the Phase 6 end-to-end sweep:
          field NAMES repeat inside a DHCP option list ("Option code", "Length",
          "Value"), so a test cannot address a row by its text. */}
      {rows.map((row, index) => {
        const isSelected = row.node.id === selectedFieldId
        const isHovered = row.node.id === hoveredFieldId
        return (
          <li
            key={row.node.id}
            ref={(element) => {
              items.current[index] = element
              if (index === focusIndex) applyFocus(index)
            }}
            role="treeitem"
            data-field-id={row.node.id}
            aria-level={row.level + 1}
            aria-selected={isSelected}
            aria-expanded={row.hasChildren ? row.expanded : undefined}
            aria-describedby="field-detail-panel"
            tabIndex={index === focusIndex ? 0 : -1}
            className={`tree-row${isSelected ? ' is-selected' : ''}${isHovered ? ' is-hovered' : ''}`}
            style={{ paddingLeft: `${row.level * 1.1 + 0.4}rem` }}
            onClick={(event) => {
              event.stopPropagation()
              setRequestedFocus(index)
              selectField(row.node.id)
            }}
            onMouseEnter={() => hoverField(row.node.id)}
          >
            {row.hasChildren ? (
              <button
                type="button"
                className="tree-twisty"
                tabIndex={-1}
                aria-label={row.expanded ? `Collapse ${row.node.name}` : `Expand ${row.node.name}`}
                onClick={(event) => {
                  event.stopPropagation()
                  toggle(row.node.id, !row.expanded)
                }}
              >
                {row.expanded ? '▾' : '▸'}
              </button>
            ) : (
              <span className="tree-twisty tree-twisty-empty" aria-hidden="true" />
            )}

            <span className="tree-name">{row.node.name}</span>
            <span className="tree-value">{row.node.value}</span>
            <span className="tree-offset" aria-hidden="true">
              {row.node.byteStart}
              {row.node.byteLength > 1 ? `–${row.node.byteStart + row.node.byteLength - 1}` : ''}
            </span>
          </li>
        )
      })}
    </ul>
  )
}

function flatten(
  nodes: readonly FieldNode[],
  collapsed: ReadonlySet<string>,
  level = 0,
  parentId: string | null = null,
  out: Row[] = [],
): Row[] {
  for (const node of nodes) {
    const hasChildren = node.children !== undefined && node.children.length > 0
    const expanded = hasChildren && !collapsed.has(node.id)
    out.push({ node, level, hasChildren, expanded, parentId })
    if (expanded && node.children) flatten(node.children, collapsed, level + 1, node.id, out)
  }
  return out
}
