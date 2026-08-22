/**
 * @vitest-environment jsdom
 *
 * The reference pages and the concept map, which have one thing in common: both
 * are generated from the registry and the spec tables, so both must change when
 * those change and neither may claim anything they do not have.
 */

import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it } from 'vitest'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { IPV4_SPECS } from '../src/core/protocols/ipv4.ts'
import { findProtocol } from '../src/core/registry.ts'
import type { FieldSpec } from '../src/core/spec.ts'
import { HomePage } from '../src/pages/HomePage.tsx'
import { ReferenceIndexPage, ReferencePage } from '../src/pages/ReferencePage.tsx'

afterEach(cleanup)

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/reference" element={<ReferenceIndexPage />} />
        <Route path="/reference/:protocol" element={<ReferencePage />} />
      </Routes>
    </MemoryRouter>,
  )
}

describe('the reference pages', () => {
  it('lists every field of a protocol exactly once, each with an explanation', () => {
    const dhcp = findProtocol('dhcp')!
    renderAt('/reference/dhcp')

    const table = screen.getByRole('table')
    for (const spec of dhcp.specs) {
      const rows = within(table).getAllByText(spec.id)
      expect(rows, `${spec.id} appears ${rows.length} times`).toHaveLength(1)
      expect(within(table).getAllByText(spec.description).length).toBeGreaterThan(0)
    }

    // And nothing extra: one row per spec field.
    expect(within(table).getAllByRole('row')).toHaveLength(dhcp.specs.length + 1)
  })

  it('links every field to a lesson packet that actually contains it', async () => {
    renderAt('/reference/ip')

    const ttl = document.getElementById('field-ip.ttl')
    const link = within(ttl as HTMLElement).getByRole('link')
    // The DHCP lesson is the only one with IPv4 in it, and its first packet has
    // a TTL, so that is where the link points. Derived, not written down.
    expect(link.getAttribute('href')).toBe('/lesson/dhcp?p=0&f=ip.ttl')
  })

  /**
   * Plan step 8.5's real claim, tested rather than asserted: the page is
   * generated. Add a field to a spec table and the page grows a row for it with
   * no edit to any page code.
   */
  it('grows a row when a field is added to a spec, with no page change', () => {
    const specs = IPV4_SPECS as FieldSpec[]
    const invented: FieldSpec = {
      id: 'ip.invented',
      name: 'Invented field',
      bits: 8,
      render: () => 'x',
      description: 'Added by a test to prove this page is generated, not written.',
    }

    const before = renderAt('/reference/ip')
    expect(screen.queryByText('ip.invented')).toBeNull()
    before.unmount()

    specs.push(invented)
    try {
      renderAt('/reference/ip')
      expect(screen.getByText('ip.invented')).toBeTruthy()
      expect(screen.getByText(invented.description)).toBeTruthy()
      // The diagram is generated from the same table, so it grew a box too.
      expect(screen.getAllByTitle(/Invented field/).length).toBeGreaterThan(0)
    } finally {
      specs.pop()
    }
  })

  it('renders value dictionaries the decoder owns, including DHCP option codes', () => {
    renderAt('/reference/dhcp')
    // Option codes come from the hand-written option loop's map, not from a
    // FieldSpec — the reference page would otherwise omit half the protocol.
    expect(screen.getByRole('region', { name: 'Option codes' })).toBeTruthy()
    expect(screen.getByRole('region', { name: 'Message types (option 53)' })).toBeTruthy()
  })

  it('refuses to invent a page for a protocol with no decoder', () => {
    renderAt('/reference/tcp')
    expect(screen.getByRole('heading', { level: 1 }).textContent).toContain('tcp')
    expect(screen.getByText(/no decoder for it/i)).toBeTruthy()
  })

  it('indexes implemented protocols as links and unimplemented ones as inert cards', () => {
    renderAt('/reference')
    expect(screen.getByRole('link', { name: /IPv4/ })).toBeTruthy()
    expect(screen.queryByRole('link', { name: /^TCP/ })).toBeNull()
    expect(screen.getAllByText('not implemented').length).toBe(3)
  })
})

describe('the concept map', () => {
  it('offers the implemented protocols and disables the rest', () => {
    renderAt('/')

    expect(screen.getByRole('button', { name: /Ethernet II/ }).hasAttribute('disabled')).toBe(false)
    expect(screen.getByRole('button', { name: /DHCP/ }).hasAttribute('disabled')).toBe(false)
    expect(screen.getByRole('button', { name: /TCP/ }).hasAttribute('disabled')).toBe(true)
    expect(screen.getByRole('button', { name: /DNS/ }).hasAttribute('disabled')).toBe(true)
  })

  it('filters the lesson cards to the ones that put a protocol on the wire', async () => {
    renderAt('/')
    await userEvent.click(screen.getByRole('button', { name: /DHCP/ }))

    // Lessons only: the import and reference cards are not lessons, so the
    // filter has nothing to say about them and leaves them alone.
    const lessons = document.querySelectorAll('.cards .card:not(.card-secondary)')
    const lit = Array.from(lessons).filter((card) => !card.classList.contains('is-dimmed'))

    expect(lessons.length).toBe(3)
    expect(lit).toHaveLength(1)
    expect(lit[0]?.querySelector('h2')?.textContent).toMatch(/DHCP/)
  })

  it('clears the filter when the same block is pressed again', async () => {
    renderAt('/')
    const arp = screen.getByRole('button', { name: /^ARP/ })

    await userEvent.click(arp)
    expect(document.querySelectorAll('.card.is-dimmed').length).toBeGreaterThan(0)

    await userEvent.click(arp)
    expect(document.querySelectorAll('.card.is-dimmed')).toHaveLength(0)
  })
})
