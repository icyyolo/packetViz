/**
 * The neighbour cache is a fold over decoded frames, so it is testable without
 * a DOM — and worth testing hard, because the spoofing lesson's entire claim is
 * that RFC 826's merge rule fires for a packet nobody asked for.
 */

import { describe, expect, it } from 'vitest'
import { cachesAt, foldArpCaches, outcomesOf, type Delivery } from '../src/core/arp-cache.ts'
import { arpMessage } from '../src/core/protocols/arp.ts'
import { arpScenario } from '../src/lessons/arp/scenario.ts'
import { arpSpoofingScenario } from '../src/lessons/arp-spoofing/scenario.ts'
import { compileScenario, type CompiledTimeline } from '../src/scenario/compile.ts'

function deliveriesOf(timeline: CompiledTimeline): Delivery[] {
  return timeline.marks.map((mark) => {
    const message = arpMessage(timeline.packets[mark.packetIndex]!)
    expect(message, `packet ${mark.packetIndex} is not ARP`).toBeDefined()
    return { packetIndex: mark.packetIndex, arrivedMs: mark.arrivedMs, message: message! }
  })
}

describe('the ARP lesson', () => {
  const timeline = compileScenario(arpScenario)
  const snapshots = foldArpCaches(timeline.hosts, deliveriesOf(timeline))

  it('starts every cache empty, which is why the first packet must be a broadcast', () => {
    const caches = cachesAt(timeline.hosts, snapshots, 0)
    for (const host of timeline.hosts) {
      expect(caches.get(host.id), `${host.id} starts with entries`).toEqual([])
    }
  })

  it('has Bob answer the request and Carol discard it', () => {
    const outcomes = outcomesOf(snapshots, 0)
    expect(outcomes.get('alice')).toBe('sent')
    expect(outcomes.get('bob')).toBe('answered')
    expect(outcomes.get('carol')).toBe('ignored')
  })

  it('teaches Alice the mapping she asked for, and nobody else anything', () => {
    const caches = cachesAt(timeline.hosts, snapshots, 620)

    expect(caches.get('alice')).toEqual([
      {
        ip: '10.0.0.2',
        mac: 'aa:bb:cc:00:00:02',
        learnedMs: 620,
        learnedFrom: 1,
        overwritten: false,
      },
    ])
    // Bob cached Alice from the request he answered; Carol overheard it and,
    // per RFC 826, did not cache a conversation she was not part of.
    expect(caches.get('bob')?.map((entry) => entry.ip)).toEqual(['10.0.0.1'])
    expect(caches.get('carol')).toEqual([])
  })

  it('drops the unicast reply at Carol\'s NIC before ARP ever sees it', () => {
    expect(outcomesOf(snapshots, 1).get('carol')).toBe('not-addressed')
  })
})

describe('the spoofing lesson', () => {
  const timeline = compileScenario(arpSpoofingScenario)
  const snapshots = foldArpCaches(timeline.hosts, deliveriesOf(timeline))
  const entryFor = (tMs: number, hostId: string, ip: string) =>
    cachesAt(timeline.hosts, snapshots, tMs)
      .get(hostId)
      ?.find((entry) => entry.ip === ip)

  it('installs the correct mapping first', () => {
    expect(entryFor(520, 'alice', '10.0.0.2')?.mac).toBe('aa:bb:cc:00:00:02')
    expect(entryFor(520, 'alice', '10.0.0.2')?.overwritten).toBe(false)
  })

  it('lets a gratuitous ARP refresh a holder without creating an entry elsewhere', () => {
    const outcomes = outcomesOf(snapshots, 2)
    expect(outcomes.get('alice')).toBe('refreshed')
    expect(outcomes.get('mallory')).toBe('ignored')
    expect(entryFor(1020, 'mallory', '10.0.0.2')).toBeUndefined()
  })

  it('overwrites the entry from an unsolicited reply — the merge rule', () => {
    const outcomes = outcomesOf(snapshots, 3)
    expect(outcomes.get('alice')).toBe('overwritten')

    const poisoned = entryFor(1520, 'alice', '10.0.0.2')
    expect(poisoned?.mac).toBe('aa:bb:cc:00:00:66')
    expect(poisoned?.overwritten).toBe(true)
    expect(poisoned?.learnedFrom).toBe(3)
  })

  it('keeps Bob unaware: the spoof is unicast, so his NIC never passes it up', () => {
    expect(outcomesOf(snapshots, 3).get('bob')).toBe('not-addressed')
    expect(entryFor(1520, 'bob', '10.0.0.1')?.mac).toBe('aa:bb:cc:00:00:01')
  })

  it('is a pure function of t: scrubbing back restores the honest entry', () => {
    expect(entryFor(1519, 'alice', '10.0.0.2')?.mac).toBe('aa:bb:cc:00:00:02')
    expect(entryFor(1520, 'alice', '10.0.0.2')?.mac).toBe('aa:bb:cc:00:00:66')
  })
})
