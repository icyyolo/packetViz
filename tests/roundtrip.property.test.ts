/**
 * Reconciles the two halves of the codec: the imperative encoder and the
 * spec-driven decoder are written independently, so agreement across 1000+
 * generated packets is evidence they describe the same wire format.
 */

import fc from 'fast-check'
import { describe, expect, it } from 'vitest'
import { findField } from '../src/core/field.ts'
import { decodeFrame } from '../src/core/registry.ts'
import { ARP_OPCODE, encodeArp } from '../src/core/protocols/arp.ts'
import { ETHER_TYPE, encodeEthernet } from '../src/core/protocols/ethernet.ts'

const RUNS = 1000

const macArb = fc
  .uint8Array({ minLength: 6, maxLength: 6 })
  .map((bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join(':'))

const ipv4Arb = fc
  .uint8Array({ minLength: 4, maxLength: 4 })
  .map((bytes) => Array.from(bytes, (b) => b.toString(10)).join('.'))

const opcodeArb = fc.oneof(
  fc.constant(ARP_OPCODE.REQUEST),
  fc.constant(ARP_OPCODE.REPLY),
  fc.integer({ min: 0, max: 0xffff }),
)

const arpArb = fc.record({
  opcode: opcodeArb,
  senderMac: macArb,
  senderIp: ipv4Arb,
  targetMac: macArb,
  targetIp: ipv4Arb,
})

describe('ARP round-trip', () => {
  it('decodes back every value the encoder wrote', () => {
    fc.assert(
      fc.property(arpArb, macArb, (arp, ethDst) => {
        const frame = encodeEthernet({
          dst: ethDst,
          src: arp.senderMac,
          etherType: ETHER_TYPE.ARP,
          payload: encodeArp(arp),
        })
        const packet = decodeFrame(frame)
        const value = (id: string): string | undefined => findField(packet.tree, id)?.value

        expect(packet.problems).toEqual([])
        expect(value('eth.dst')).toBe(ethDst)
        expect(value('eth.src')).toBe(arp.senderMac)
        expect(value('arp.src.hw_mac')).toBe(arp.senderMac)
        expect(value('arp.src.proto_ipv4')).toBe(arp.senderIp)
        expect(value('arp.dst.hw_mac')).toBe(arp.targetMac)
        expect(value('arp.dst.proto_ipv4')).toBe(arp.targetIp)

        const opcode = findField(packet.tree, 'arp.opcode')
        expect(opcode?.raw[0]).toBe(arp.opcode >> 8)
        expect(opcode?.raw[1]).toBe(arp.opcode & 0xff)
      }),
      { numRuns: RUNS },
    )
  })

  it('always produces a frame of at least the Ethernet minimum', () => {
    fc.assert(
      fc.property(arpArb, macArb, (arp, ethDst) => {
        const frame = encodeEthernet({
          dst: ethDst,
          src: arp.senderMac,
          etherType: ETHER_TYPE.ARP,
          payload: encodeArp(arp),
        })
        expect(frame.length).toBe(60)
      }),
      { numRuns: RUNS },
    )
  })
})
