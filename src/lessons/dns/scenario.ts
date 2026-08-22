/**
 * Scene intent for the DNS lesson.
 *
 * Deliberately absent from this file: the record type, the class, the flags, the
 * fact that the answer's name is a compression pointer. All of that lives in
 * `src/core/protocols/dns.ts`. What remains is who asks whom, for what name,
 * what the answer is, and how long it may be cached.
 */

import { buildDnsQueryFrame, buildDnsResponseFrame } from '../../core/protocols/dns.ts'
import type { Scenario } from '../../scenario/types.ts'

const laptop = { id: 'laptop', label: 'Laptop', mac: 'aa:bb:cc:00:00:05', ip: '10.0.0.50' }
const resolver = { id: 'resolver', label: 'Resolver', mac: 'aa:bb:cc:00:00:01', ip: '10.0.0.1' }

const hostname = 'files.corp.internal'

/**
 * The two numbers the client picks for itself. Both are guessing targets: an
 * attacker who can predict them can answer before the real resolver does, which
 * is why the source is randomised as hard as the transaction id.
 */
const clientPick = { ephemeral: 41234, id: 0x1a2b }

/** What the resolver knows, and how long a client may keep it. */
const answer = { address: '10.0.0.9', ttl: 300 }

export const dnsScenario: Scenario = {
  hosts: [laptop, resolver],
  linkDelayMs: 120,
  events: [
    {
      tMs: 0,
      from: laptop.id,
      to: resolver.id,
      build: () => buildDnsQueryFrame(laptop, resolver, clientPick, hostname),
    },
    {
      tMs: 500,
      from: resolver.id,
      to: laptop.id,
      build: () => buildDnsResponseFrame(resolver, laptop, clientPick, hostname, answer),
    },
  ],
}
