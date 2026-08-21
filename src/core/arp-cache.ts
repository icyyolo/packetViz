/**
 * What ARP is *for*: the table it fills in.
 *
 * The four layers show a packet. This shows the consequence of the packet — the
 * neighbour cache each host ends up holding, which is the only reason ARP is on
 * the wire at all. Everything here is a fold over decoded frames; no state is
 * read from a lesson.
 *
 * Reception follows RFC 826 §"Packet Reception", which is short and worth
 * quoting because two of its properties are the entire security story:
 *
 *   - If the sender protocol address is ALREADY in my table, update its hardware
 *     address. Unconditionally. No check that I asked, no check that the sender
 *     is who it claims. This is the merge rule, and it is why an unsolicited
 *     reply can overwrite a correct entry.
 *   - Otherwise, only add an entry if I am the target — so a host does not cache
 *     every conversation it overhears.
 *
 * A host that hears a frame addressed to another MAC never gets here at all: the
 * NIC filters it first, which is modelled by `frameDst`.
 */

import { ARP_OPCODE, type ArpMessage } from './protocols/arp.ts'
import { BROADCAST_MAC } from './protocols/ethernet.ts'

/** Structural, so `scenario.Host` satisfies it without core importing scenario. */
export type CacheOwner = {
  id: string
  mac: string
  ip: string
}

export type ArpCacheEntry = {
  ip: string
  mac: string
  /** Arrival time of the frame that installed this value. */
  learnedMs: number
  learnedFrom: number
  /** True when this entry replaced a DIFFERENT MAC for the same IP — the poisoning signal. */
  overwritten: boolean
}

/**
 * What one host did with one frame.
 *
 * `not-addressed` is the NIC dropping it before ARP ever sees it; `ignored` is
 * ARP itself declining to cache a conversation it merely overheard.
 */
export type Reception =
  | 'sent'
  | 'not-addressed'
  | 'ignored'
  | 'learned'
  | 'refreshed'
  | 'overwritten'
  | 'answered'

export type Delivery = {
  packetIndex: number
  arrivedMs: number
  message: ArpMessage
}

export type CacheSnapshot = {
  packetIndex: number
  arrivedMs: number
  /** Host id -> what that host did with this frame. */
  outcomes: Map<string, Reception>
  /** Host id -> its cache immediately after this delivery. */
  caches: Map<string, ArpCacheEntry[]>
}

/**
 * Replay every delivery in order, snapshotting each host's cache after each one.
 * Snapshots are cumulative and immutable, so `cachesAt` is a lookup rather than
 * a re-simulation on every frame of the timeline.
 */
export function foldArpCaches(
  hosts: readonly CacheOwner[],
  deliveries: readonly Delivery[],
): CacheSnapshot[] {
  const live = new Map<string, Map<string, ArpCacheEntry>>(
    hosts.map((host) => [host.id, new Map<string, ArpCacheEntry>()]),
  )
  const snapshots: CacheSnapshot[] = []

  for (const delivery of [...deliveries].sort((a, b) => a.arrivedMs - b.arrivedMs)) {
    const outcomes = new Map<string, Reception>()

    for (const host of hosts) {
      const table = live.get(host.id)
      if (table === undefined) continue
      outcomes.set(host.id, receive(host, table, delivery))
    }

    snapshots.push({
      packetIndex: delivery.packetIndex,
      arrivedMs: delivery.arrivedMs,
      outcomes,
      caches: new Map([...live].map(([id, table]) => [id, [...table.values()]])),
    })
  }

  return snapshots
}

function receive(
  host: CacheOwner,
  table: Map<string, ArpCacheEntry>,
  delivery: Delivery,
): Reception {
  const { message, arrivedMs, packetIndex } = delivery

  // The sender does not receive its own transmission.
  if (message.senderMac === host.mac) return 'sent'

  // NIC filter: unicast to somebody else never reaches the ARP layer.
  if (message.frameDst !== BROADCAST_MAC && message.frameDst !== host.mac) {
    return 'not-addressed'
  }

  const existing = table.get(message.senderIp)
  const install = (overwritten: boolean): void => {
    table.set(message.senderIp, {
      ip: message.senderIp,
      mac: message.senderMac,
      learnedMs: arrivedMs,
      learnedFrom: packetIndex,
      overwritten,
    })
  }

  // The merge rule. Note what is NOT checked here.
  if (existing !== undefined) {
    const changed = existing.mac !== message.senderMac
    install(changed || existing.overwritten)
    return changed ? 'overwritten' : 'refreshed'
  }

  if (message.targetIp === host.ip) {
    install(false)
    return message.opcode === ARP_OPCODE.REQUEST ? 'answered' : 'learned'
  }

  return 'ignored'
}

/** The caches as of `tMs`: the last snapshot to have arrived, or empty tables. */
export function cachesAt(
  hosts: readonly CacheOwner[],
  snapshots: readonly CacheSnapshot[],
  tMs: number,
): Map<string, ArpCacheEntry[]> {
  let current: CacheSnapshot | undefined
  for (const snapshot of snapshots) {
    if (snapshot.arrivedMs <= tMs) current = snapshot
  }
  if (current !== undefined) return current.caches
  return new Map(hosts.map((host) => [host.id, []]))
}

/** What each host did with packet `packetIndex`, or an empty map if it never arrived. */
export function outcomesOf(
  snapshots: readonly CacheSnapshot[],
  packetIndex: number,
): Map<string, Reception> {
  return snapshots.find((s) => s.packetIndex === packetIndex)?.outcomes ?? new Map()
}
