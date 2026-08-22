/**
 * An imported capture, compiled into the same timeline a lesson produces.
 *
 * A lesson knows its cast in advance because someone wrote the scenario. A
 * capture does not: the only thing that arrived is bytes. So the hosts here are
 * DERIVED — every distinct Ethernet address the frames themselves carry becomes
 * a lifeline, and its IP annotation is read out of the IPv4 header of a packet
 * it sent. That keeps the invariant intact in the one place it would have been
 * easiest to break: nothing on screen is typed by a human, including the names.
 *
 * What a capture genuinely does not contain is propagation delay. It holds one
 * timestamp per packet, taken at one observation point, so `linkDelayMs` is 0
 * and the ladder's arrows are flat. Inventing a slope would be inventing a
 * measurement.
 */

import { findField, type DecodedPacket } from '../core/field.ts'
import { formatIpv4, formatMac } from '../core/format.ts'
import { frameAt, relativeMs, type PcapCapture, type PcapRecord } from '../core/pcap/read.ts'
import { decodeFrame } from '../core/registry.ts'
import type { CompiledTimeline, TimelineMark } from './compile.ts'
import type { Host } from './types.ts'

const TAIL_MS = 400

/**
 * Beyond this many packets a ladder diagram stops being a diagram and the
 * decode of every frame stops being free, so the import page shows the packet
 * list alone and decodes only what is selected. Layers 3 and 4 work at any size.
 */
export const LADDER_MAX_PACKETS = 32

/** Whether the stage (topology + ladder) is worth drawing for this capture. */
export function isLadderSized(capture: PcapCapture): boolean {
  return capture.totalRecords <= LADDER_MAX_PACKETS
}

export function compileCapture(capture: PcapCapture): CompiledTimeline {
  const packets = capture.records.map((record) => decodeFrame(frameAt(capture, record)))
  const marks: TimelineMark[] = capture.records.map((record, index) =>
    markOf(capture, record, index, packets[index]),
  )

  const lastArrival = marks.reduce((max, mark) => Math.max(max, mark.arrivedMs), 0)

  return {
    hosts: hostsOf(packets),
    linkDelayMs: 0,
    packets,
    marks,
    durationMs: lastArrival + TAIL_MS,
  }
}

function markOf(
  capture: PcapCapture,
  record: PcapRecord,
  index: number,
  packet: DecodedPacket | undefined,
): TimelineMark {
  const tMs = relativeMs(capture, record)
  const dst = packet === undefined ? undefined : macOf(packet, 'eth.dst')
  return {
    packetIndex: index,
    sentMs: tMs,
    arrivedMs: tMs,
    from: packet === undefined ? 'unknown' : (macOf(packet, 'eth.src') ?? 'unknown'),
    // A group address reaches everyone on the segment, which the ladder draws
    // the same way a lesson's broadcast is drawn.
    to: dst === undefined || isGroupAddress(dst) ? null : dst,
  }
}

/**
 * One host per Ethernet address seen, in the order the capture introduces them.
 * The IP annotation is whatever address that host was last seen sourcing, so a
 * DHCP client that starts at 0.0.0.0 ends up labelled with the address it got.
 */
function hostsOf(packets: readonly DecodedPacket[]): Host[] {
  const hosts = new Map<string, Host>()

  const see = (mac: string | undefined, ip: string | undefined): void => {
    if (mac === undefined || isGroupAddress(mac)) return
    const existing = hosts.get(mac)
    if (existing === undefined) {
      hosts.set(mac, { id: mac, label: ip ?? mac, mac, ip: ip ?? '' })
      return
    }
    if (ip !== undefined && ip !== '0.0.0.0') {
      existing.ip = ip
      existing.label = ip
    }
  }

  for (const packet of packets) {
    see(macOf(packet, 'eth.src'), ipOf(packet, 'ip.src') ?? ipOf(packet, 'arp.src.proto_ipv4'))
    see(macOf(packet, 'eth.dst'), undefined)
  }

  return Array.from(hosts.values())
}

function macOf(packet: DecodedPacket, fieldId: string): string | undefined {
  const node = findField(packet.tree, fieldId)
  return node === undefined || node.raw.length !== 6 ? undefined : formatMac(node.raw)
}

function ipOf(packet: DecodedPacket, fieldId: string): string | undefined {
  const node = findField(packet.tree, fieldId)
  return node === undefined || node.raw.length !== 4 ? undefined : formatIpv4(node.raw)
}

/** Broadcast and multicast both set the low bit of the first octet (IEEE 802.3 §3.2.3). */
function isGroupAddress(mac: string): boolean {
  const first = Number.parseInt(mac.slice(0, 2), 16)
  return Number.isFinite(first) && (first & 1) === 1
}
