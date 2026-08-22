/**
 * The two-packet ARP exchange used by the pcap and Wireshark differential tests.
 * The frames come from `core`, exactly as the lesson scenario builds them.
 */

import { buildArpReplyFrame, buildArpRequestFrame } from '../src/core/protocols/arp.ts'
import {
  buildDhcpAckFrame,
  buildDhcpDiscoverFrame,
  buildDhcpOfferFrame,
  buildDhcpRequestFrame,
} from '../src/core/protocols/dhcp.ts'
import type { PcapPacket } from '../src/core/pcap/write.ts'
import type { Scenario } from '../src/scenario/types.ts'
import { compileScenario } from '../src/scenario/compile.ts'

export const HOST_A = { mac: 'aa:bb:cc:00:00:01', ip: '10.0.0.1' }
export const HOST_B = { mac: 'aa:bb:cc:00:00:02', ip: '10.0.0.2' }

export function arpRequestFrame(): Uint8Array {
  return buildArpRequestFrame(HOST_A, HOST_B.ip)
}

export function arpReplyFrame(): Uint8Array {
  return buildArpReplyFrame(HOST_B, HOST_A)
}

export function arpExchange(): PcapPacket[] {
  return [
    { frame: arpRequestFrame(), tMs: 0 },
    { frame: arpReplyFrame(), tMs: 12 },
  ]
}

/**
 * A whole lesson as a capture, exactly as `ExportPcapButton` writes it: the
 * compiled frames, timestamped at transmission. Lets the Wireshark differential
 * run over the same bytes a visitor downloads.
 */
export function lessonCapture(scenario: Scenario): PcapPacket[] {
  const timeline = compileScenario(scenario)
  return timeline.packets.map((packet, index) => ({
    frame: packet.frame,
    tMs: timeline.marks[index]?.sentMs ?? 0,
  }))
}

export const DHCP_CLIENT = { mac: '00:11:22:33:44:55' }

export const DHCP_LEASE = {
  serverMac: 'aa:bb:cc:00:00:01',
  serverIp: '10.0.0.1',
  clientIp: '10.0.0.50',
  subnetMask: '255.255.255.0',
  router: '10.0.0.1',
  dns: '10.0.0.1',
  leaseSeconds: 86400,
}

/** The four messages of a DORA exchange, as the Phase 5 lesson will send them. */
export function dhcpExchange(): PcapPacket[] {
  const xid = 0x3903f326
  return [
    { frame: buildDhcpDiscoverFrame(DHCP_CLIENT, xid), tMs: 0 },
    { frame: buildDhcpOfferFrame(DHCP_CLIENT, DHCP_LEASE, xid), tMs: 20 },
    { frame: buildDhcpRequestFrame(DHCP_CLIENT, DHCP_LEASE, xid), tMs: 40 },
    { frame: buildDhcpAckFrame(DHCP_CLIENT, DHCP_LEASE, xid), tMs: 60 },
  ]
}
