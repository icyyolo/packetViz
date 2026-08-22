/**
 * @vitest-environment jsdom
 *
 * Phase 7 from the outside: a file goes in, four layers come out — or a message
 * does. These are the cases that decide whether a stranger's capture is usable,
 * and the ones where "it went blank" would be the worst outcome.
 */

import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { ByteWriter } from '../src/core/bytes.ts'
import { PCAP_SNAPLEN, writePcap } from '../src/core/pcap/write.ts'
import { encodeEthernet, ETHER_TYPE } from '../src/core/protocols/ethernet.ts'
import { encodeIpv4 } from '../src/core/protocols/ipv4.ts'
import { ImportPage } from '../src/pages/ImportPage.tsx'
import { compileScenario } from '../src/scenario/compile.ts'
import { dhcpScenario } from '../src/lessons/dhcp/scenario.ts'
import { arpRequestFrame, dhcpExchange } from './fixtures.ts'

afterEach(cleanup)

async function importBytes(bytes: Uint8Array, name = 'capture.pcap'): Promise<void> {
  render(
    <MemoryRouter initialEntries={['/import']}>
      <ImportPage />
    </MemoryRouter>,
  )
  const input = screen.getByLabelText('Capture file')
  await userEvent.upload(input, new File([bytes as BlobPart], name))
}

/** A pcap our own writer would never produce: a link type we refuse. */
function rawIpPcap(): Uint8Array {
  const bytes = new Uint8Array(24 + 16 + 4)
  const view = new DataView(bytes.buffer)
  view.setUint32(0, 0xd4c3b2a1, false)
  view.setUint16(4, 2, true)
  view.setUint16(6, 4, true)
  view.setUint32(16, PCAP_SNAPLEN, true)
  view.setUint32(20, 101, true) // LINKTYPE_RAW
  view.setUint32(24 + 8, 4, true)
  view.setUint32(24 + 12, 4, true)
  return bytes
}

/**
 * Ethernet + IPv4 + OSPF. We have no OSPF decoder, which is the point: the
 * payload has to survive as bytes rather than as a crash or a blank pane. This
 * used to be a TCP segment, until TCP got a decoder — an imported capture
 * carries protocols we have not implemented, and always will.
 */
const OSPF_PROTOCOL = 89

function undecodedFrame(): Uint8Array {
  const ospf = new ByteWriter()
    .u8(2) // version
    .u8(1) // type: Hello
    .u16be(44) // packet length
    .u32be(0x0a00_0001) // router id
    .u32be(0) // area id
    .u16be(0) // checksum
    .u16be(0) // auth type
    .finish()

  return encodeEthernet({
    dst: 'aa:bb:cc:00:00:02',
    src: 'aa:bb:cc:00:00:01',
    etherType: ETHER_TYPE.IPV4,
    payload: encodeIpv4({
      src: '10.0.0.1',
      dst: '10.0.0.2',
      protocol: OSPF_PROTOCOL,
      ttl: 64,
      identification: 0x1234,
      payload: ospf,
    }),
  })
}

describe('importing a capture', () => {
  it('decodes an exported lesson back to the same four packets', async () => {
    const expected = compileScenario(dhcpScenario)
    await importBytes(writePcap(dhcpExchange()), 'dhcp.pcap')

    await waitFor(() => expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('dhcp.pcap'))

    // The list, the summaries and the field values all come from the imported
    // bytes; that they equal the lesson's is the round trip working.
    const tabs = document.querySelectorAll('.packet-tab')
    expect(tabs).toHaveLength(expected.packets.length)
    expect(Array.from(tabs, (tab) => tab.querySelector('.packet-tab-summary')?.textContent)).toEqual(
      expected.packets.map((packet) => packet.summary),
    )

    expect(screen.getByRole('tree')).toBeTruthy()
    expect(document.querySelector('.hex-grid')).toBeTruthy()
    expect(document.querySelectorAll('.problem.is-error')).toHaveLength(0)

    // Layers 1 and 2 are drawn, with hosts derived from the frames' own addresses.
    expect(document.querySelector('.topology')).toBeTruthy()
    expect(document.querySelector('.flow')).toBeTruthy()
    expect(screen.getAllByText('10.0.0.1').length).toBeGreaterThan(0)
  })

  it('reports the byte order and packet count it found', async () => {
    await importBytes(writePcap(dhcpExchange()), 'dhcp.pcap')
    await waitFor(() =>
      expect(document.querySelector('.lesson-blurb')?.textContent).toMatch(
        /4 packets, big-endian, microsecond timestamps/,
      ),
    )
  })

  it('explains a file that is not a pcap instead of rendering nothing', async () => {
    // 4 KB of noise, deterministic so the failure is reproducible.
    const noise = Uint8Array.from({ length: 4096 }, (_, i) => (i * 37 + 11) & 0xff)
    await importBytes(noise, 'urandom.pcap')

    expect((await screen.findByRole('alert')).textContent).toMatch(/Not a pcap file/)
    // Still interactive: the dropzone is right there to try again.
    expect(screen.getByLabelText('Capture file')).toBeTruthy()
  })

  it('names the link-layer type it cannot decode', async () => {
    await importBytes(rawIpPcap(), 'raw.pcap')
    expect((await screen.findByRole('alert')).textContent).toMatch(/101 \(raw IP\)/)
  })

  it('shows a protocol it has no decoder for as raw bytes, still linked to the hex', async () => {
    await importBytes(writePcap([{ frame: undecodedFrame(), tMs: 0 }]), 'ospf.pcap')

    await waitFor(() => expect(document.querySelector('.hex-grid')).toBeTruthy())
    const tree = screen.getByRole('tree')
    expect(within(tree).getByText('Payload (no decoder)')).toBeTruthy()

    // A warning, not an error: the frame decoded fine, we simply stop at OSPF.
    const problems = document.querySelectorAll('.problem')
    expect(problems).toHaveLength(1)
    expect(problems[0]?.textContent).toMatch(/No decoder for IP protocol 89/)
    expect(document.querySelectorAll('.problem.is-error')).toHaveLength(0)
  })

  it('drops the ladder for a capture too big to draw, and decodes only what is selected', async () => {
    const frame = arpRequestFrame()
    const many = Array.from({ length: 40 }, (_, index) => ({ frame, tMs: index * 5 }))
    await importBytes(writePcap(many), 'big.pcap')

    await waitFor(() => expect(document.querySelectorAll('.packet-tab')).toHaveLength(40))
    expect(document.querySelector('.flow')).toBeNull()
    expect(document.querySelector('.capture-note')?.textContent).toMatch(/only one decoded/i)

    // Rows carry a timestamp rather than a summary, because nothing was decoded
    // to summarise; selecting one decodes it.
    const tabs = document.querySelectorAll('.packet-tab')
    expect(tabs[36]?.querySelector('.packet-tab-summary')?.textContent).toMatch(/^\+0\.180000 s$/)

    await userEvent.click(tabs[36] as HTMLElement)
    expect(screen.getByRole('tree')).toBeTruthy()
    expect(document.querySelector('.packet-tab.is-active')?.textContent).toContain('#37')
  })

  it('says how many packets it left out when a capture exceeds the cap', async () => {
    const frame = arpRequestFrame()
    const many = Array.from({ length: 5010 }, (_, index) => ({ frame, tMs: index }))
    await importBytes(writePcap(many), 'huge.pcap')

    expect((await screen.findByRole('status')).textContent).toMatch(
      /Showing the first 5000 packets of 5010/,
    )
  })
})
