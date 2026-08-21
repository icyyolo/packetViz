/**
 * Scene intent only.
 *
 * Who is on the segment, how long the wire takes, who transmits when — and, for
 * this lesson, who lies about whom. That last part is still scene intent: which
 * address Mallory claims is a fact about the story, not about the wire format.
 * The frame she sends is built by the same `core` encoder that builds an honest
 * reply, because on the wire a spoofed reply IS an honest reply. Nothing in this
 * file says what an ARP packet contains.
 */

import {
  buildArpReplyFrame,
  buildArpRequestFrame,
  buildGratuitousArpFrame,
} from '../../core/protocols/arp.ts'
import type { Scenario } from '../../scenario/types.ts'

const alice = { id: 'alice', label: 'Alice', mac: 'aa:bb:cc:00:00:01', ip: '10.0.0.1' }
const bob = { id: 'bob', label: 'Bob', mac: 'aa:bb:cc:00:00:02', ip: '10.0.0.2' }
const mallory = { id: 'mallory', label: 'Mallory', mac: 'aa:bb:cc:00:00:66', ip: '10.0.0.66' }

export const arpSpoofingScenario: Scenario = {
  hosts: [alice, bob, mallory],
  linkDelayMs: 120,
  events: [
    { tMs: 0, from: alice.id, to: null, build: () => buildArpRequestFrame(alice, bob.ip) },
    { tMs: 400, from: bob.id, to: alice.id, build: () => buildArpReplyFrame(bob, alice) },
    { tMs: 900, from: bob.id, to: null, build: () => buildGratuitousArpFrame(bob) },
    {
      tMs: 1400,
      from: mallory.id,
      to: alice.id,
      // Mallory's own address never appears in the frame she sends: she signs it
      // with her hardware address and Bob's IP address.
      build: () => buildArpReplyFrame({ mac: mallory.mac, ip: bob.ip }, alice),
    },
  ],
}
