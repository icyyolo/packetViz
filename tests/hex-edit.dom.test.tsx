/**
 * @vitest-environment jsdom
 *
 * Phase 3.5: layer 4 is writable, and this is the test that makes the
 * single-source-of-truth invariant falsifiable rather than merely claimed.
 *
 * Typing over one byte must move every other layer, because no layer holds a
 * copy of anything: flipping the ARP opcode byte relabels the ladder arrow, the
 * packet tab, the field tree and the detail panel, all from a fresh decode of
 * the new buffer. Phase 6 adds the Playwright version in a real browser; this
 * is the floor that runs on every commit without one.
 */

import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it } from 'vitest'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { LessonPage } from '../src/pages/LessonPage.tsx'

afterEach(cleanup)

function renderLesson() {
  return render(
    <MemoryRouter initialEntries={['/lesson/arp']}>
      <Routes>
        <Route path="/lesson/:slug" element={<LessonPage />} />
      </Routes>
    </MemoryRouter>,
  )
}

/** The ARP opcode's low byte: Ethernet header (14) + 6 bytes of ARP + one. */
const OPCODE_LOW = 21

const cell = (offset: number, value: number): HTMLElement =>
  screen.getByLabelText(`Byte ${offset}, value 0x${value.toString(16).padStart(2, '0')}`)

const tabSummaries = (): string[] =>
  Array.from(document.querySelectorAll('.packet-tab-summary'), (node) => node.textContent ?? '')

/** Text of the field-tree row for a named field, value included. */
const treeValue = (name: string): string =>
  Array.from(document.querySelectorAll('[role="tree"] .tree-row'))
    .find((row) => row.textContent?.includes(name))
    ?.textContent ?? ''

describe('editing a byte', () => {
  it('re-decodes every layer from the new buffer', async () => {
    const user = userEvent.setup()
    renderLesson()

    expect(tabSummaries()[0]).toBe('Who has 10.0.0.2? Tell 10.0.0.1')
    expect(treeValue('Opcode')).toContain('1 (Request)')

    // Type 0, then 2, over the opcode's low byte: a request becomes a reply.
    await user.click(cell(OPCODE_LOW, 0x01))
    await user.keyboard('02')

    // Layer 3: the field tree and the detail panel.
    expect(treeValue('Opcode')).toContain('2 (Reply)')
    expect(within(document.getElementById('field-detail-panel') as HTMLElement).getByText('Reply')).toBeTruthy()

    // Layer 4: the byte itself, marked as differing from the scenario's bytes.
    const edited = cell(OPCODE_LOW, 0x02)
    expect(edited.className).toContain('is-edited')

    // Layers 1 and 2, plus the packet tab: all read `DecodedPacket.summary`,
    // which is derived from the same bytes and now says the opposite thing.
    expect(tabSummaries()[0]).toBe('10.0.0.1 is at aa:bb:cc:00:00:01')
    const labels = Array.from(document.querySelectorAll('.flow-label'), (n) => n.textContent)
    expect(labels[0]).toBe('10.0.0.1 is at aa:bb:cc:00:00:01')

    // ...and the packet is flagged as no longer the lesson's.
    expect(screen.getAllByText('modified').length).toBeGreaterThan(0)
  })

  it('restores the scenario bytes on reset', async () => {
    const user = userEvent.setup()
    renderLesson()

    await user.click(cell(OPCODE_LOW, 0x01))
    await user.keyboard('02')
    expect(tabSummaries()[0]).toBe('10.0.0.1 is at aa:bb:cc:00:00:01')

    // Reset only drops the override — which is proof the edit never mutated the
    // scenario's own buffer, because there is nothing else left to restore from.
    await user.click(screen.getByRole('button', { name: /Reset to the scenario/ }))

    expect(tabSummaries()[0]).toBe('Who has 10.0.0.2? Tell 10.0.0.1')
    expect(treeValue('Opcode')).toContain('1 (Request)')
    expect(screen.queryByText('modified')).toBeNull()
    expect(cell(OPCODE_LOW, 0x01).className).not.toContain('is-edited')
  })

  it('holds a half-typed byte until the second digit, and Escape drops it', async () => {
    const user = userEvent.setup()
    renderLesson()

    await user.click(cell(OPCODE_LOW, 0x01))
    await user.keyboard('f')

    const typing = document.querySelector('.hex-cell.is-typing')
    expect(typing?.textContent).toBe('f_')
    // Nothing has changed yet: one nibble is not a byte.
    expect(tabSummaries()[0]).toBe('Who has 10.0.0.2? Tell 10.0.0.1')

    await user.keyboard('{Escape}')
    expect(document.querySelector('.hex-cell.is-typing')).toBeNull()
    expect(cell(OPCODE_LOW, 0x01)).toBeTruthy()
  })

  it('nudges a byte by one with + and -, without moving the roving focus', async () => {
    const user = userEvent.setup()
    renderLesson()

    await user.click(cell(OPCODE_LOW, 0x01))
    await user.keyboard('+')
    expect(treeValue('Opcode')).toContain('2 (Reply)')
    expect(document.activeElement?.getAttribute('aria-label')).toBe('Byte 21, value 0x02')

    await user.keyboard('-')
    expect(treeValue('Opcode')).toContain('1 (Request)')
  })

  it('surfaces a decoder problem for bytes that no longer make sense', async () => {
    const user = userEvent.setup()
    renderLesson()

    // The hardware-address length: 0xff is a claim the frame cannot back, and
    // tshark calls the same edit a malformed packet (tshark-diff.test.ts).
    await user.click(cell(18, 0x06))
    await user.keyboard('ff')

    const problems = screen.getByRole('list', { name: 'Decoder problems' })
    expect(within(problems).getByText(/6-byte hardware addresses/)).toBeTruthy()
    expect(document.querySelector('.hex-cell.is-error')).toBeTruthy()
  })
})
