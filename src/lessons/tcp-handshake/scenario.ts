/**
 * Scene intent for the TCP handshake lesson.
 *
 * Deliberately absent from this file: the flags, the well-known destination
 * port, the options, the window sizes, the rule that a SYN consumes a sequence
 * number. All of that lives in `src/core/protocols/tcp.ts`. What remains is who
 * connects to whom, the random numbers each end picks for itself, and when.
 */

import {
  buildTcpAckFrame,
  buildTcpSynAckFrame,
  buildTcpSynFrame,
} from '../../core/protocols/tcp.ts'
import type { Scenario } from '../../scenario/types.ts'

const laptop = { id: 'laptop', label: 'Laptop', mac: 'aa:bb:cc:00:00:05', ip: '10.0.0.50' }
const server = { id: 'server', label: 'Web server', mac: 'aa:bb:cc:00:00:09', ip: '10.0.0.9' }

/**
 * The two numbers each end picks at random for itself. Choosing them badly is a
 * security problem with its own RFC — 6528 — because anything that can guess the
 * other end's starting number can inject data into the stream.
 */
const clientPick = { ephemeral: 52341, sequence: 0x1f2e3d4c }
const serverPick = { sequence: 0xa1b2c3d4 }

export const tcpHandshakeScenario: Scenario = {
  hosts: [laptop, server],
  linkDelayMs: 120,
  events: [
    {
      tMs: 0,
      from: laptop.id,
      to: server.id,
      build: () => buildTcpSynFrame(laptop, server, clientPick),
    },
    {
      tMs: 400,
      from: server.id,
      to: laptop.id,
      build: () => buildTcpSynAckFrame(server, laptop, serverPick, clientPick),
    },
    {
      tMs: 800,
      from: laptop.id,
      to: server.id,
      build: () => buildTcpAckFrame(laptop, server, clientPick, serverPick),
    },
  ],
}
