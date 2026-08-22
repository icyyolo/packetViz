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
import { BROADCAST_MAC, ETHER_TYPE, encodeEthernet } from '../src/core/protocols/ethernet.ts'
import { IP_PROTOCOL, encodeIpv4 } from '../src/core/protocols/ipv4.ts'
import { encodeUdp } from '../src/core/protocols/udp.ts'
import {
  DHCP_CLIENT_PORT,
  DHCP_MESSAGE_TYPE_NAMES,
  DHCP_OPTION,
  DHCP_OP,
  DHCP_SERVER_PORT,
  encodeDhcp,
  optionIpv4,
  optionU32,
  optionU8,
} from '../src/core/protocols/dhcp.ts'

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

/**
 * The full stack: Ethernet -> IPv4 -> UDP -> DHCP, generated end to end.
 *
 * This is the strongest evidence in the project that the two halves of the codec
 * describe the same wire format. It also checks a thousand random checksums,
 * over both the IPv4 header and the UDP pseudo-header, in each direction: the
 * encoder computes them and the decoder recomputes them from the bytes, and
 * neither can see the other's arithmetic.
 */

const dhcpArb = fc.record({
  clientMac: macArb,
  serverIp: ipv4Arb,
  clientIp: ipv4Arb,
  subnetMask: ipv4Arb,
  xid: fc.integer({ min: 0, max: 0xffffffff }),
  secs: fc.integer({ min: 0, max: 0xffff }),
  broadcast: fc.boolean(),
  messageType: fc.integer({ min: 1, max: 8 }),
  leaseSeconds: fc.integer({ min: 0, max: 0xffffffff }),
})

describe('DHCP over UDP over IPv4 round-trip', () => {
  it('decodes back every value the encoders wrote, checksums included', () => {
    fc.assert(
      fc.property(dhcpArb, (input) => {
        const dhcp = encodeDhcp({
          op: DHCP_OP.REPLY,
          xid: input.xid,
          secs: input.secs,
          broadcast: input.broadcast,
          clientIp: '0.0.0.0',
          yourIp: input.clientIp,
          serverIp: '0.0.0.0',
          relayIp: '0.0.0.0',
          clientMac: input.clientMac,
          options: [
            { code: DHCP_OPTION.MESSAGE_TYPE, value: optionU8(input.messageType) },
            { code: DHCP_OPTION.SERVER_ID, value: optionIpv4(input.serverIp) },
            { code: DHCP_OPTION.LEASE_TIME, value: optionU32(input.leaseSeconds) },
            { code: DHCP_OPTION.SUBNET_MASK, value: optionIpv4(input.subnetMask) },
          ],
        })
        const frame = encodeEthernet({
          dst: BROADCAST_MAC,
          src: input.clientMac,
          etherType: ETHER_TYPE.IPV4,
          payload: encodeIpv4({
            src: input.serverIp,
            dst: input.clientIp,
            protocol: IP_PROTOCOL.UDP,
            ttl: 64,
            identification: input.xid & 0xffff,
            payload: encodeUdp({
              srcPort: DHCP_SERVER_PORT,
              dstPort: DHCP_CLIENT_PORT,
              srcIp: input.serverIp,
              dstIp: input.clientIp,
              payload: dhcp,
            }),
          }),
        })

        const packet = decodeFrame(frame)
        const value = (id: string): string | undefined => findField(packet.tree, id)?.value

        // No problems at all means: version, both lengths, the magic cookie, the
        // IPv4 checksum and the UDP checksum all verified against the bytes.
        expect(packet.problems).toEqual([])
        expect(value('ip.src')).toBe(input.serverIp)
        expect(value('ip.dst')).toBe(input.clientIp)
        expect(value('ip.checksum')).toContain('[correct]')
        expect(value('udp.checksum')).toContain('[correct]')
        expect(value('dhcp.ip.your')).toBe(input.clientIp)
        expect(value('dhcp.hw.mac_addr')).toBe(input.clientMac)
        expect(value('dhcp.secs')).toBe(`${input.secs} seconds`)
        expect(value('dhcp.opt.53.value')).toBe(
          `${input.messageType} (${DHCP_MESSAGE_TYPE_NAMES[input.messageType]})`,
        )
        expect(value('dhcp.opt.54.value')).toBe(input.serverIp)
        expect(value('dhcp.opt.51.value')).toBe(`${input.leaseSeconds} seconds`)
        expect(value('dhcp.opt.1.value')).toBe(input.subnetMask)
        expect(packet.summary).toBe(`DHCP ${DHCP_MESSAGE_TYPE_NAMES[input.messageType]}`)
      }),
      { numRuns: RUNS },
    )
  })
})
