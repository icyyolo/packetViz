/**
 * IPv4: sub-byte fields, two untrusted lengths and a checksum. Each of those is
 * a way for a packet to lie, so most of this file is about what the decoder does
 * when one does.
 */

import { describe, expect, it } from 'vitest'
import { ipv4Checksum } from '../src/core/checksum.ts'
import { findField } from '../src/core/field.ts'
import { ETHER_TYPE, ETH_HEADER_BYTES, encodeEthernet } from '../src/core/protocols/ethernet.ts'
import { IPV4_HEADER_BYTES, IP_PROTOCOL, encodeIpv4, decodeIpv4 } from '../src/core/protocols/ipv4.ts'
import { UDP_HEADER_BYTES, encodeUdp } from '../src/core/protocols/udp.ts'
import { decodeFrame } from '../src/core/registry.ts'
import { toHex } from './util.ts'

const DATA = Uint8Array.from([0xde, 0xad, 0xbe, 0xef])

/** A whole frame: Ethernet, IPv4, and a small UDP datagram to a port nothing decodes. */
function ipv4Frame(protocol: number = IP_PROTOCOL.UDP): Uint8Array {
  const payload =
    protocol === IP_PROTOCOL.UDP
      ? encodeUdp({ srcPort: 9, dstPort: 9, srcIp: '10.0.0.1', dstIp: '10.0.0.2', payload: new Uint8Array(0) })
      : DATA
  return encodeEthernet({
    dst: 'aa:bb:cc:00:00:02',
    src: 'aa:bb:cc:00:00:01',
    etherType: ETHER_TYPE.IPV4,
    payload: encodeIpv4({
      src: '10.0.0.1',
      dst: '10.0.0.2',
      protocol,
      ttl: 64,
      identification: 0x1234,
      payload,
    }),
  })
}

/** An empty UDP datagram: legal, and it keeps these tests about IPv4. */
const IP_PAYLOAD_BYTES = UDP_HEADER_BYTES

describe('IPv4', () => {
  it('encodes a header byte-for-byte against a hand-written literal', () => {
    const header = encodeIpv4({
      src: '10.0.0.1',
      dst: '10.0.0.2',
      protocol: IP_PROTOCOL.UDP,
      ttl: 64,
      identification: 0x1234,
      payload: DATA,
    })
    // version 4, IHL 5 -> 0x45; DSCP/ECN 0; total length 20 + 4 = 24;
    // id 0x1234; no flags, no fragment; TTL 64 = 0x40; protocol 17 = 0x11.
    expect(toHex(header.subarray(0, 10))).toBe('4500' + '0018' + '1234' + '0000' + '4011')
    expect(toHex(header.subarray(12, 20))).toBe('0a000001' + '0a000002')
    expect(header.length).toBe(IPV4_HEADER_BYTES + DATA.length)
  })

  it('stamps a checksum the header verifies against', () => {
    const packet = decodeFrame(ipv4Frame())
    expect(packet.problems).toEqual([])
    expect(findField(packet.tree, 'ip.checksum')?.value).toContain('[correct]')
  })

  it('splits the shared bytes into sub-byte fields with bit offsets', () => {
    const packet = decodeFrame(ipv4Frame())
    const version = findField(packet.tree, 'ip.version')
    const ihl = findField(packet.tree, 'ip.hdr_len')

    expect(version?.byteStart).toBe(ETH_HEADER_BYTES)
    expect(version?.byteLength).toBe(1)
    expect(version?.bitOffset).toBe(0)
    expect(version?.bitLength).toBe(4)
    expect(version?.value).toBe('4')

    // Same byte, second nibble — which is why hex highlighting is per byte and
    // the bit range is shown in the tree instead.
    expect(ihl?.byteStart).toBe(ETH_HEADER_BYTES)
    expect(ihl?.bitOffset).toBe(4)
    expect(ihl?.value).toBe('5 words (20 bytes)')

    const fragment = findField(packet.tree, 'ip.frag_offset')
    expect(fragment?.bitOffset).toBe(3)
    expect(fragment?.bitLength).toBe(13)
  })

  it('reports a corrupted checksum and says what it should have been', () => {
    const frame = Uint8Array.from(ipv4Frame())
    frame[ETH_HEADER_BYTES + 10] = (frame[ETH_HEADER_BYTES + 10] ?? 0) ^ 0xff

    const packet = decodeFrame(frame)
    expect(packet.problems).toHaveLength(1)
    expect(packet.problems[0]?.severity).toBe('warning')
    expect(packet.problems[0]?.message).toContain('a router would discard this packet')
    expect(findField(packet.tree, 'ip.checksum')?.value).toContain('should be')

    // A warning does not stop the decode: the payload is still there to look at.
    expect(findField(packet.tree, 'ip.dst')?.value).toBe('10.0.0.2')
  })

  it('refuses a header length below the five-word minimum', () => {
    const frame = Uint8Array.from(ipv4Frame())
    frame[ETH_HEADER_BYTES] = 0x43 // version 4, IHL 3

    const packet = decodeFrame(frame)
    expect(packet.problems.some((problem) => problem.message.includes('below the minimum'))).toBe(true)
    expect(packet.problems.every((problem) => problem.byteStart >= ETH_HEADER_BYTES)).toBe(true)
  })

  it('reports a total length that runs past the frame, and reads nothing beyond it', () => {
    const frame = Uint8Array.from(ipv4Frame())
    frame[ETH_HEADER_BYTES + 2] = 0xff
    frame[ETH_HEADER_BYTES + 3] = 0xff

    const packet = decodeFrame(frame)
    expect(packet.problems.some((problem) => problem.message.includes('only'))).toBe(true)
    for (const problem of packet.problems) {
      expect(problem.byteStart + problem.byteLength).toBeLessThanOrEqual(frame.length)
    }
  })

  it('treats bytes past the total length as padding, not as payload', () => {
    // An Ethernet frame is padded to 60 bytes; IPv4 says how much of it is real.
    const frame = ipv4Frame()
    expect(frame.length).toBe(60)

    const packet = decodeFrame(frame)
    const padding = findField(packet.tree, 'eth.padding')
    expect(padding?.byteStart).toBe(ETH_HEADER_BYTES + IPV4_HEADER_BYTES + IP_PAYLOAD_BYTES)
  })

  it('carries options through as raw bytes when the header is longer than five words', () => {
    // Built by hand rather than by the encoder, which only emits option-free
    // headers: this is a frame we might be given, not one we would produce.
    const header = Uint8Array.from(
      encodeIpv4({
        src: '10.0.0.1',
        dst: '10.0.0.2',
        protocol: 253, // reserved for experiments; nothing decodes it
        ttl: 64,
        identification: 1,
        payload: new Uint8Array(0),
      }),
    )
    const withOption = new Uint8Array(24)
    withOption.set(header, 0)
    withOption[0] = 0x46 // IHL 6: one four-byte option follows the fixed fields
    withOption[3] = 24 // total length
    withOption[10] = 0
    withOption[11] = 0
    const sum = ipv4Checksum(withOption)
    withOption[10] = sum >> 8
    withOption[11] = sum & 0xff

    const decoded = decodeIpv4(withOption, 0)
    const options = decoded.nodes[0]?.children?.find((child) => child.id === 'ip.options')
    expect(decoded.problems).toEqual([])
    expect(options?.byteStart).toBe(IPV4_HEADER_BYTES)
    expect(options?.byteLength).toBe(4)
    expect(decoded.payloadOffset).toBe(24)
  })

  it('shows an unknown payload protocol as raw bytes instead of guessing', () => {
    const packet = decodeFrame(ipv4Frame(6))
    expect(packet.problems.map((problem) => problem.severity)).toEqual(['warning'])
    expect(packet.problems[0]?.message).toContain('No decoder for IP protocol 6')
    const data = findField(packet.tree, 'data')
    expect(data?.byteStart).toBe(ETH_HEADER_BYTES + IPV4_HEADER_BYTES)
    // Bounded by IPv4's own total length: the Ethernet padding after it belongs
    // to no protocol and is still reported as padding.
    expect(data?.byteLength).toBe(DATA.length)
    expect(findField(packet.tree, 'eth.padding')).toBeDefined()
  })
})
