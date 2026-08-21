/**
 * Scene intent for the ARP lesson.
 *
 * Deliberately absent from this file: EtherTypes, opcodes, hardware/protocol
 * type numbers, address-length fields, the broadcast destination. All of that is
 * protocol knowledge and lives in `src/core/protocols/arp.ts`, where the frame
 * builders encode it once. What remains here is who is on the segment, how far
 * apart they are in milliseconds, and who transmits when.
 *
 * `npm run test` asserts this file contains no protocol-field literals.
 */

import { buildArpReplyFrame, buildArpRequestFrame } from '../../core/protocols/arp.ts'
import type { Scenario } from '../../scenario/types.ts'

const alice = { id: 'alice', label: 'Alice', mac: 'aa:bb:cc:00:00:01', ip: '10.0.0.1' }
const bob = { id: 'bob', label: 'Bob', mac: 'aa:bb:cc:00:00:02', ip: '10.0.0.2' }
const carol = { id: 'carol', label: 'Carol', mac: 'aa:bb:cc:00:00:03', ip: '10.0.0.3' }

export const arpScenario: Scenario = {
  hosts: [alice, bob, carol],
  linkDelayMs: 120,
  events: [
    {
      tMs: 0,
      from: alice.id,
      to: null, // broadcast: Alice does not yet know who to address
      build: () => buildArpRequestFrame(alice, bob.ip),
    },
    {
      tMs: 500,
      from: bob.id,
      to: alice.id,
      build: () => buildArpReplyFrame(bob, alice),
    },
  ],
}
