/**
 * Scene intent for the ping lesson.
 *
 * Deliberately absent from this file: the message types, the code byte, the
 * checksum, the payload, the time to live. All of that is protocol knowledge and
 * lives in `src/core/protocols/icmp.ts`. What remains is who pings whom, what
 * numbers the ping process picked for itself, and when each frame goes out.
 */

import {
  buildIcmpEchoReplyFrame,
  buildIcmpEchoRequestFrame,
} from '../../core/protocols/icmp.ts'
import type { Scenario } from '../../scenario/types.ts'

const laptop = { id: 'laptop', label: 'Laptop', mac: 'aa:bb:cc:00:00:05', ip: '10.0.0.50' }
const server = { id: 'server', label: 'File server', mac: 'aa:bb:cc:00:00:09', ip: '10.0.0.9' }

/**
 * The number the ping process picked to recognise its own replies — on Linux,
 * its process id. Nothing else ties a reply to the program that asked for it.
 */
const process = 0x1a2b

export const pingScenario: Scenario = {
  hosts: [laptop, server],
  linkDelayMs: 120,
  events: [
    {
      tMs: 0,
      from: laptop.id,
      to: server.id,
      build: () => buildIcmpEchoRequestFrame(laptop, server, { identifier: process, sequence: 1 }),
    },
    {
      tMs: 200,
      from: server.id,
      to: laptop.id,
      build: () => buildIcmpEchoReplyFrame(server, laptop, { identifier: process, sequence: 1 }),
    },
    {
      tMs: 1000,
      from: laptop.id,
      to: server.id,
      build: () => buildIcmpEchoRequestFrame(laptop, server, { identifier: process, sequence: 2 }),
    },
    {
      tMs: 1200,
      from: server.id,
      to: laptop.id,
      build: () => buildIcmpEchoReplyFrame(server, laptop, { identifier: process, sequence: 2 }),
    },
  ],
}
