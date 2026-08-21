/**
 * @vitest-environment jsdom
 *
 * The signature feature, exercised end to end in a real DOM: click a field, its
 * bytes light up; click a byte, its field lights up. Phase 6 replaces this with
 * an exhaustive Playwright sweep over every leaf of every packet; until then
 * this proves the wiring actually works rather than merely compiles.
 */

import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it } from 'vitest'
import { leafFields } from '../src/core/field.ts'
import { arpScenario } from '../src/lessons/arp/scenario.ts'
import { compileScenario } from '../src/scenario/compile.ts'
import { FieldDetailPanel } from '../src/views/FieldDetailPanel.tsx'
import { FieldTreeView } from '../src/views/FieldTreeView.tsx'
import { HexView } from '../src/views/HexView.tsx'
import { SelectionProvider } from '../src/views/SelectionContext.tsx'

afterEach(cleanup)

const timeline = compileScenario(arpScenario)
const packet = timeline.packets[0]!

function renderLinkedViews() {
  return render(
    <SelectionProvider packetCount={timeline.packets.length}>
      <FieldTreeView packet={packet} />
      <HexView packet={packet} />
      <FieldDetailPanel packet={packet} />
    </SelectionProvider>,
  )
}

/** The hex cells currently highlighted, as byte offsets. */
function selectedOffsets(): number[] {
  return Array.from(document.querySelectorAll('.hex-cell.is-selected')).map((cell) =>
    Number.parseInt(cell.getAttribute('aria-label')?.match(/Byte (\d+)/)?.[1] ?? '-1', 10),
  )
}

describe('field <-> byte linking', () => {
  it('renders one hex cell per byte of the frame', () => {
    renderLinkedViews()
    expect(document.querySelectorAll('.hex-cell:not(.hex-empty)')).toHaveLength(packet.frame.length)
    expect(packet.frame.length).toBe(60)
  })

  it('lights up bytes 6–11 when the source MAC field is clicked', async () => {
    const user = userEvent.setup()
    renderLinkedViews()

    await user.click(screen.getByText('Source MAC address'))
    expect(selectedOffsets()).toEqual([6, 7, 8, 9, 10, 11])
  })

  it('selects arp.opcode when byte 20 is clicked', async () => {
    const user = userEvent.setup()
    renderLinkedViews()

    await user.click(screen.getByLabelText('Byte 20, value 0x00'))

    const selectedRow = document.querySelector('.tree-row.is-selected')
    expect(selectedRow?.textContent).toContain('Opcode')
    expect(selectedOffsets()).toEqual([20, 21])
  })

  it('fills the detail panel from the FieldSpec table, not from a lesson file', async () => {
    const user = userEvent.setup()
    renderLinkedViews()

    await user.click(screen.getByLabelText('Byte 20, value 0x00'))
    const panel = within(document.getElementById('field-detail-panel') as HTMLElement)

    expect(panel.getByText('Opcode')).toBeTruthy()
    expect(panel.getByText('1 (Request)')).toBeTruthy()
    expect(panel.getByText('Request')).toBeTruthy()
    expect(panel.getByText('RFC 826 §2')).toBeTruthy()
    expect(panel.getByText(/who has this IP address/i)).toBeTruthy()
  })

  it('round-trips every leaf field: field -> bytes -> same field', async () => {
    const user = userEvent.setup()
    renderLinkedViews()

    let checked = 0
    for (const node of leafFields(packet.tree)) {
      await user.click(screen.getByText(node.name))

      const expected = Array.from({ length: node.byteLength }, (_x, i) => node.byteStart + i)
      expect(selectedOffsets(), `selecting ${node.id} highlighted the wrong bytes`).toEqual(expected)

      // ...and back the other way, from a byte inside the span.
      const byte = packet.frame[node.byteStart]!
      await user.click(
        screen.getByLabelText(`Byte ${node.byteStart}, value 0x${byte.toString(16).padStart(2, '0')}`),
      )
      expect(document.querySelector('.tree-row.is-selected')?.textContent).toContain(node.name)
      checked += 1
    }

    expect(checked).toBe(Array.from(leafFields(packet.tree)).length)
    expect(checked).toBeGreaterThanOrEqual(13)
  })
})

describe('keyboard operation', () => {
  it('walks the hex grid with arrow keys and selects with Enter', async () => {
    const user = userEvent.setup()
    renderLinkedViews()

    await user.tab() // into the tree
    await user.tab() // into the hex grid
    expect(document.activeElement?.getAttribute('aria-label')).toBe('Byte 0, value 0xff')

    // Byte 20 is one row down (16 bytes) and four columns across.
    await user.keyboard('{ArrowDown}')
    for (let i = 0; i < 4; i++) await user.keyboard('{ArrowRight}')
    expect(document.activeElement?.getAttribute('aria-label')).toContain('Byte 20')

    await user.keyboard('{Enter}')
    expect(document.querySelector('.tree-row.is-selected')?.textContent).toContain('Opcode')
    expect(selectedOffsets()).toEqual([20, 21])
  })

  it('clamps the roving focus at the end of the frame', async () => {
    const user = userEvent.setup()
    renderLinkedViews()

    await user.tab()
    await user.tab()
    for (let i = 0; i < 8; i++) await user.keyboard('{ArrowDown}')
    expect(document.activeElement?.getAttribute('aria-label')).toBe('Byte 59, value 0x00')
  })

  it('exposes the tree as an ARIA tree with expandable protocol nodes', async () => {
    const user = userEvent.setup()
    renderLinkedViews()

    const tree = screen.getByRole('tree', { name: 'Decoded fields' })
    expect(within(tree).getAllByRole('treeitem').length).toBeGreaterThan(10)

    await user.click(screen.getByLabelText('Collapse Address Resolution Protocol'))
    expect(screen.queryByText('Opcode')).toBeNull()

    await user.click(screen.getByLabelText('Expand Address Resolution Protocol'))
    expect(screen.getByText('Opcode')).toBeTruthy()
  })

  it('marks selection with a non-colour cue as well as a colour', async () => {
    const user = userEvent.setup()
    renderLinkedViews()

    await user.click(screen.getByText('Opcode'))
    const cell = document.querySelector('.hex-cell.is-selected')
    // The stylesheet gives `.is-selected` an outline and an underline; the class
    // is the contract the greyscale check in 3.13 relies on.
    expect(cell?.classList.contains('is-selected')).toBe(true)
    expect(document.querySelector('.tree-row.is-selected')).toBeTruthy()
  })
})
