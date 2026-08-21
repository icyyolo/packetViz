import { describe, expect, it } from 'vitest'
import { findField, leafFields } from '../src/core/field.ts'
import { decodeFrame } from '../src/core/registry.ts'
import {
  ARP_OPCODE,
  ARP_PAYLOAD_BYTES,
  ARP_SPECS,
  encodeArp,
} from '../src/core/protocols/arp.ts'
import {
  BROADCAST_MAC,
  ETHER_TYPE,
  ETH_HEADER_BYTES,
  encodeEthernet,
} from '../src/core/protocols/ethernet.ts'
import { fromHex, toHex } from './util.ts'

const HOST_A = { mac: 'aa:bb:cc:00:00:01', ip: '10.0.0.1' }
const HOST_B = { mac: 'aa:bb:cc:00:00:02', ip: '10.0.0.2' }

const request = encodeArp({
  opcode: ARP_OPCODE.REQUEST,
  senderMac: HOST_A.mac,
  senderIp: HOST_A.ip,
  targetMac: '00:00:00:00:00:00',
  targetIp: HOST_B.ip,
})

function framed(payload: Uint8Array, dst: string, src: string): Uint8Array {
  return encodeEthernet({ dst, src, etherType: ETHER_TYPE.ARP, payload })
}

describe('ARP', () => {
  it('encodes a request byte-for-byte against a hand-written literal', () => {
    // htype=1 ptype=0x0800 hlen=6 plen=4 op=1
    // sender aa:bb:cc:00:00:01 / 10.0.0.1, target 00:00:00:00:00:00 / 10.0.0.2
    const expected =
      '0001' + '0800' + '06' + '04' + '0001' +
      'aabbcc000001' + '0a000001' +
      '000000000000' + '0a000002'

    expect(request.length).toBe(ARP_PAYLOAD_BYTES)
    expect(ARP_PAYLOAD_BYTES).toBe(28)
    expect(toHex(request)).toBe(expected)
    expect(request).toEqual(fromHex(expected))
  })

  it('puts the opcode at frame offset 20 and reads it back as Request', () => {
    const packet = decodeFrame(framed(request, BROADCAST_MAC, HOST_A.mac))
    const opcode = findField(packet.tree, 'arp.opcode')

    expect(opcode).toMatchObject({
      byteStart: ETH_HEADER_BYTES + 6,
      byteLength: 2,
      value: '1 (Request)',
    })
    expect(opcode?.byteStart).toBe(20)
    expect(packet.problems).toEqual([])
  })

  it('decodes every ARP field at its absolute frame offset', () => {
    const packet = decodeFrame(framed(request, BROADCAST_MAC, HOST_A.mac))
    const arp = leafFields([findField(packet.tree, 'arp') as never])

    expect(Array.from(arp, (n) => [n.id, n.byteStart, n.byteLength, n.value])).toEqual([
      ['arp.hw.type', 14, 2, '1 (Ethernet)'],
      ['arp.proto.type', 16, 2, '0x0800 (IPv4)'],
      ['arp.hw.size', 18, 1, '6 bytes'],
      ['arp.proto.size', 19, 1, '4 bytes'],
      ['arp.opcode', 20, 2, '1 (Request)'],
      ['arp.src.hw_mac', 22, 6, HOST_A.mac],
      ['arp.src.proto_ipv4', 28, 4, HOST_A.ip],
      ['arp.dst.hw_mac', 32, 6, '00:00:00:00:00:00'],
      ['arp.dst.proto_ipv4', 38, 4, HOST_B.ip],
    ])
  })

  it('summarises request and reply the way Wireshark does', () => {
    const requestPacket = decodeFrame(framed(request, BROADCAST_MAC, HOST_A.mac))
    expect(requestPacket.summary).toBe('Who has 10.0.0.2? Tell 10.0.0.1')

    const reply = encodeArp({
      opcode: ARP_OPCODE.REPLY,
      senderMac: HOST_B.mac,
      senderIp: HOST_B.ip,
      targetMac: HOST_A.mac,
      targetIp: HOST_A.ip,
    })
    expect(decodeFrame(framed(reply, HOST_A.mac, HOST_B.mac)).summary).toBe(
      '10.0.0.2 is at aa:bb:cc:00:00:02',
    )
  })

  it('shows an unknown opcode rather than hiding it', () => {
    const odd = encodeArp({
      opcode: 9,
      senderMac: HOST_A.mac,
      senderIp: HOST_A.ip,
      targetMac: HOST_B.mac,
      targetIp: HOST_B.ip,
    })
    const packet = decodeFrame(framed(odd, HOST_B.mac, HOST_A.mac))
    expect(findField(packet.tree, 'arp.opcode')?.value).toBe('9 (unknown)')
  })

  it('explains every field it decodes', () => {
    for (const spec of ARP_SPECS) {
      expect(spec.description.length, `${spec.id} has no description`).toBeGreaterThan(0)
      expect(spec.reference, `${spec.id} has no RFC reference`).toBeDefined()
    }
  })
})
