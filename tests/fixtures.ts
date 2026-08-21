/**
 * The two-packet ARP exchange used by the pcap and Wireshark differential tests.
 * Phase 3 replaces this with `src/lessons/arp/scenario.ts`; until the scenario
 * layer exists, the tests build their traffic here.
 */

import { ARP_OPCODE, encodeArp } from '../src/core/protocols/arp.ts'
import { BROADCAST_MAC, ETHER_TYPE, encodeEthernet } from '../src/core/protocols/ethernet.ts'
import type { PcapPacket } from '../src/core/pcap/write.ts'

export const HOST_A = { mac: 'aa:bb:cc:00:00:01', ip: '10.0.0.1' }
export const HOST_B = { mac: 'aa:bb:cc:00:00:02', ip: '10.0.0.2' }
export const UNSPECIFIED_MAC = '00:00:00:00:00:00'

export function arpRequestFrame(): Uint8Array {
  return encodeEthernet({
    dst: BROADCAST_MAC,
    src: HOST_A.mac,
    etherType: ETHER_TYPE.ARP,
    payload: encodeArp({
      opcode: ARP_OPCODE.REQUEST,
      senderMac: HOST_A.mac,
      senderIp: HOST_A.ip,
      targetMac: UNSPECIFIED_MAC,
      targetIp: HOST_B.ip,
    }),
  })
}

export function arpReplyFrame(): Uint8Array {
  return encodeEthernet({
    dst: HOST_A.mac,
    src: HOST_B.mac,
    etherType: ETHER_TYPE.ARP,
    payload: encodeArp({
      opcode: ARP_OPCODE.REPLY,
      senderMac: HOST_B.mac,
      senderIp: HOST_B.ip,
      targetMac: HOST_A.mac,
      targetIp: HOST_A.ip,
    }),
  })
}

export function arpExchange(): PcapPacket[] {
  return [
    { frame: arpRequestFrame(), tMs: 0 },
    { frame: arpReplyFrame(), tMs: 12 },
  ]
}
