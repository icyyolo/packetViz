/**
 * @vitest-environment jsdom
 *
 * Routing and deep links: a lesson is reachable by URL, and a URL carries the
 * selection down to the field (lesson criterion #5).
 */

import { cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it } from 'vitest'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { HomePage } from '../src/pages/HomePage.tsx'
import { LessonPage } from '../src/pages/LessonPage.tsx'

afterEach(cleanup)

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/lesson/:slug" element={<LessonPage />} />
      </Routes>
    </MemoryRouter>,
  )
}

describe('routing', () => {
  it('loads a lesson directly by slug', () => {
    renderAt('/lesson/arp')
    expect(screen.getByRole('heading', { level: 1 }).textContent).toContain('ARP')
    expect(screen.getAllByRole('button', { name: /Packet 1/ }).length).toBeGreaterThan(0)
  })

  it('shows a message for an unknown slug instead of a blank screen', () => {
    renderAt('/lesson/does-not-exist')
    expect(screen.getByRole('heading', { level: 1 }).textContent).toContain('does-not-exist')
    expect(screen.getByText(/may not be built yet/i)).toBeTruthy()
  })

  it('derives home-page card badges from the decode, not from the registry', () => {
    renderAt('/')
    const card = screen.getByRole('link', { name: /ARP/ })
    expect(within(card).getByText('2 packets')).toBeTruthy()
    expect(within(card).getByText('ETH')).toBeTruthy()
    expect(within(card).getByText('ARP')).toBeTruthy()
  })
})

describe('deep links', () => {
  it('restores packet, selected field and scrubber position from ?p= and ?f=', () => {
    renderAt('/lesson/arp?p=1&f=arp.opcode')

    // Packet 2 is the active tab...
    const activeTab = document.querySelector('.packet-tab.is-active')
    expect(activeTab?.textContent).toContain('#2')
    expect(activeTab?.textContent).toContain('is at')

    // ...its opcode field is selected, and its bytes are highlighted.
    expect(document.querySelector('.tree-row.is-selected')?.textContent).toContain('Opcode')
    expect(document.querySelectorAll('.hex-cell.is-selected')).toHaveLength(2)

    // ...and the clock sits at that packet's arrival.
    expect(screen.getByLabelText('Timeline position in milliseconds')).toHaveProperty('value', '620')
  })

  it('selects nothing for an unknown field id, rather than erroring', () => {
    renderAt('/lesson/arp?p=0&f=nope.not.a.field')
    expect(document.querySelector('.tree-row.is-selected')).toBeNull()
    expect(document.querySelectorAll('.hex-cell.is-selected')).toHaveLength(0)
    expect(screen.getByRole('heading', { level: 1 }).textContent).toContain('ARP')
  })

  it('ignores an out-of-range packet index', () => {
    renderAt('/lesson/arp?p=99')
    expect(document.querySelector('.packet-tab.is-active')?.textContent).toContain('#2')
  })

  it('writes the selection back into the query string', async () => {
    const user = userEvent.setup()
    renderAt('/lesson/arp')

    // Scoped to the field tree: the generic layout table names the same field.
    const tree = document.querySelector('[role="tree"]') as HTMLElement
    await user.click(within(tree).getByText('Sender IP address'))
    expect(document.querySelector('.hex-cell.is-selected')).toBeTruthy()
    expect(document.querySelectorAll('.hex-cell.is-selected')).toHaveLength(4)
  })
})

describe('the four layers render together', () => {
  it('shows topology, ladder, field tree and hex for the same packet', () => {
    renderAt('/lesson/arp')

    expect(screen.getByRole('img', { name: 'Network topology' })).toBeTruthy()
    expect(screen.getByRole('img', { name: 'Message ladder diagram' })).toBeTruthy()
    expect(screen.getByRole('tree', { name: 'Decoded fields' })).toBeTruthy()
    expect(screen.getByRole('grid', { name: /Frame bytes/ })).toBeTruthy()
    expect(screen.getByRole('button', { name: /Export arp\.pcap/ })).toBeTruthy()
  })

  it('labels the ladder arrows from the decode summary', () => {
    renderAt('/lesson/arp')
    expect(screen.getAllByText('Who has 10.0.0.2? Tell 10.0.0.1').length).toBeGreaterThan(0)
    expect(screen.getAllByText('10.0.0.2 is at aa:bb:cc:00:00:02').length).toBeGreaterThan(0)
  })

  it('advances the narration when the timeline is scrubbed', () => {
    renderAt('/lesson/arp')

    const narration = document.querySelector('.narration') as HTMLElement
    const slider = screen.getByLabelText('Timeline position in milliseconds')

    fireEvent.change(slider, { target: { value: '0' } })
    expect(narration.textContent).toContain('Alice asks the whole segment')

    fireEvent.change(slider, { target: { value: '600' } })
    expect(narration.textContent).toContain('Bob answers')

    // Every layer follows the same `t`: the ladder playhead moved with it.
    expect(document.querySelector('.flow-playhead text')?.textContent).toBe('600 ms')
  })
})
