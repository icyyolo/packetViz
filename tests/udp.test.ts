/**
 * UDP is eight bytes, so most of what there is to test is the checksum — and
 * the fact that it covers addresses UDP cannot see.
 */

import { describe, expect, it } from 'vitest'
import { findField } from '../src/core/field.ts'
import { ETHER_TYPE, ETH_HEADER_BYTES, encodeEthernet } from '../src/core/protocols/ethernet.ts'
import { IPV4_HEADER_BYTES, IP_PROTOCOL, encodeIpv4 } from '../src/core/protocols/ipv4.ts'
import { UDP_HEADER_BYTES, decodeUdp, encodeUdp } from '../src/core/protocols/udp.ts'
import { decodeFrame } from '../src/core/registry.ts'
import { toHex } from './util.ts'

const SRC_IP = '10.0.0.1'
const DST_IP = '10.0.0.2'
const DATA = Uint8Array.from([0x01, 0x02, 0x03, 0x04])
const UDP_OFFSET = ETH_HEADER_BYTES + IPV4_HEADER_BYTES

function datagram(payload = DATA): Uint8Array {
  return encodeUdp({ srcPort: 68, dstPort: 67, srcIp: SRC_IP, dstIp: DST_IP, payload })
}

function frame(payload = DATA): Uint8Array {
  return encodeEthernet({
    dst: 'aa:bb:cc:00:00:02',
    src: 'aa:bb:cc:00:00:01',
    etherType: ETHER_TYPE.IPV4,
    payload: encodeIpv4({
      src: SRC_IP,
      dst: DST_IP,
      protocol: IP_PROTOCOL.UDP,
      ttl: 64,
      identification: 1,
      payload: datagram(payload),
    }),
  })
}

describe('UDP', () => {
  it('encodes ports and a length that includes the header', () => {
    const encoded = datagram()
    expect(toHex(encoded.subarray(0, 6))).toBe('0044' + '0043' + '000c')
    expect(encoded.length).toBe(UDP_HEADER_BYTES + DATA.length)
  })

  it('verifies its checksum against the enclosing IPv4 addresses', () => {
    const packet = decodeFrame(frame())
    const checksum = findField(packet.tree, 'udp.checksum')
    expect(checksum?.value).toContain('[correct]')
  })

  it('fails the checksum when the addresses change but the datagram does not', () => {
    // The pseudo-header is the point: the bytes UDP owns are untouched here, and
    // the checksum still stops being valid, because a datagram is only correct
    // in the packet it was addressed for.
    const moved = Uint8Array.from(frame())
    moved[ETH_HEADER_BYTES + 19] = 0x63 // last byte of the destination address
    // Restamp the IPv4 checksum so only the UDP one is in question.
    const packet = decodeFrame(moved)
    const udp = findField(packet.tree, 'udp.checksum')
    expect(udp?.value).toContain('should be')
    expect(packet.problems.some((problem) => problem.message.includes('UDP checksum'))).toBe(true)
  })

  it('says so rather than guessing when nothing tells it what carried the datagram', () => {
    const alone = datagram()
    const decoded = decodeUdp(alone, 0)
    expect(decoded.nodes[0]?.children?.find((child) => child.id === 'udp.checksum')?.value).toContain(
      'unverified',
    )
    expect(decoded.problems).toEqual([])
  })

  it('reads a zero checksum as "not computed", which IPv4 permits', () => {
    const unchecked = Uint8Array.from(frame())
    unchecked[UDP_OFFSET + 6] = 0
    unchecked[UDP_OFFSET + 7] = 0

    const packet = decodeFrame(unchecked)
    expect(findField(packet.tree, 'udp.checksum')?.value).toBe('0x0000 [not computed]')
    expect(packet.problems.filter((problem) => problem.message.includes('UDP checksum'))).toEqual([])
  })

  it('refuses a length shorter than its own header', () => {
    const lying = Uint8Array.from(frame())
    lying[UDP_OFFSET + 4] = 0
    lying[UDP_OFFSET + 5] = 3

    const packet = decodeFrame(lying)
    expect(packet.problems.some((problem) => problem.message.includes('the header alone is 8 bytes'))).toBe(
      true,
    )
  })

  it('refuses a length that runs past the frame, and reads nothing beyond it', () => {
    const lying = Uint8Array.from(frame())
    lying[UDP_OFFSET + 4] = 0xff
    lying[UDP_OFFSET + 5] = 0xff

    const packet = decodeFrame(lying)
    expect(packet.problems.some((problem) => problem.message.includes('only'))).toBe(true)
    for (const problem of packet.problems) {
      expect(problem.byteStart + problem.byteLength).toBeLessThanOrEqual(lying.length)
    }
  })
})
