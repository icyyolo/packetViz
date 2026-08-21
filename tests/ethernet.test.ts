import { describe, expect, it } from 'vitest'
import { findField } from '../src/core/field.ts'
import { decodeFrame } from '../src/core/registry.ts'
import { specBytes } from '../src/core/spec.ts'
import { encodeArp, ARP_OPCODE, ARP_PAYLOAD_BYTES } from '../src/core/protocols/arp.ts'
import {
  BROADCAST_MAC,
  ETHER_TYPE,
  ETHERNET_SPECS,
  ETH_HEADER_BYTES,
  ETH_MIN_FRAME_BYTES,
  encodeEthernet,
} from '../src/core/protocols/ethernet.ts'
import { toHex } from './util.ts'

const arpPayload = encodeArp({
  opcode: ARP_OPCODE.REQUEST,
  senderMac: 'aa:bb:cc:00:00:01',
  senderIp: '10.0.0.1',
  targetMac: '00:00:00:00:00:00',
  targetIp: '10.0.0.2',
})

const frame = encodeEthernet({
  dst: BROADCAST_MAC,
  src: 'aa:bb:cc:00:00:01',
  etherType: ETHER_TYPE.ARP,
  payload: arpPayload,
})

describe('Ethernet II', () => {
  it('agrees with its own spec table on header size', () => {
    expect(specBytes(ETHERNET_SPECS)).toBe(ETH_HEADER_BYTES)
  })

  it('pads a 42-byte ARP frame up to the 60-byte captured minimum', () => {
    expect(ETH_HEADER_BYTES + ARP_PAYLOAD_BYTES).toBe(42)
    expect(frame.length).toBe(ETH_MIN_FRAME_BYTES)
  })

  it('decodes dst/src/type at offsets 0, 6 and 12', () => {
    const packet = decodeFrame(frame)
    expect(packet.problems).toEqual([])

    expect(findField(packet.tree, 'eth.dst')).toMatchObject({
      byteStart: 0,
      byteLength: 6,
      value: BROADCAST_MAC,
    })
    expect(findField(packet.tree, 'eth.src')).toMatchObject({
      byteStart: 6,
      byteLength: 6,
      value: 'aa:bb:cc:00:00:01',
    })
    expect(findField(packet.tree, 'eth.type')).toMatchObject({
      byteStart: 12,
      byteLength: 2,
      value: '0x0806 (ARP)',
    })
  })

  it('exposes the padding as its own field, owned by no protocol', () => {
    const padding = findField(decodeFrame(frame).tree, 'eth.padding')
    expect(padding).toMatchObject({ byteStart: 42, byteLength: 18 })
    expect(toHex(padding?.raw as Uint8Array)).toBe('00'.repeat(18))
  })

  it('shows an unknown EtherType as raw bytes with a warning, not a crash', () => {
    const unknown = encodeEthernet({
      dst: BROADCAST_MAC,
      src: 'aa:bb:cc:00:00:01',
      etherType: 0x88cc,
      payload: new Uint8Array([1, 2, 3]),
    })
    const packet = decodeFrame(unknown)

    expect(findField(packet.tree, 'data')).toMatchObject({ byteStart: 14, byteLength: 46 })
    expect(packet.problems).toHaveLength(1)
    expect(packet.problems[0]?.severity).toBe('warning')
    expect(packet.problems[0]?.message).toContain('0x88cc')
  })

  it('reports truncation instead of throwing on a short frame', () => {
    const packet = decodeFrame(frame.subarray(0, 13))
    expect(packet.problems[0]?.message).toContain('Truncated at EtherType')
    expect(findField(packet.tree, 'eth.src')).toBeDefined()
    expect(findField(packet.tree, 'eth.type')).toBeUndefined()
  })
})
