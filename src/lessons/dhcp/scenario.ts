/**
 * Scene intent for the DHCP lesson.
 *
 * Deliberately absent from this file: ports, the broadcast address, the
 * broadcast flag, option codes, the magic cookie, TTLs, message types. All of
 * that is protocol knowledge and lives in `src/core/protocols/dhcp.ts`, where
 * the four frame builders encode it once. What remains here is who is on the
 * segment, what address the server has to give away, how long the lease runs,
 * and who transmits when.
 *
 * `npm run test` asserts this file contains no protocol-field literals.
 */

import {
  buildDhcpAckFrame,
  buildDhcpDiscoverFrame,
  buildDhcpOfferFrame,
  buildDhcpRequestFrame,
} from '../../core/protocols/dhcp.ts'
import type { Scenario } from '../../scenario/types.ts'

/** The client has no address yet — that is the entire problem it is trying to solve. */
const client = { id: 'client', label: 'Client', mac: '00:11:22:33:44:55', ip: '0.0.0.0' }
const server = { id: 'server', label: 'DHCP server', mac: 'aa:bb:cc:00:00:01', ip: '10.0.0.1' }
const printer = { id: 'printer', label: 'Printer', mac: 'aa:bb:cc:00:00:09', ip: '10.0.0.9' }

/**
 * A random number the client picks to recognise the answers to its own
 * questions. Nothing else ties these four messages together.
 */
const transaction = 0x3903f326

const lease = {
  serverMac: server.mac,
  serverIp: server.ip,
  clientIp: '10.0.0.50',
  subnetMask: '255.255.255.0',
  router: '10.0.0.1',
  dns: '10.0.0.1',
  leaseSeconds: 86400,
}

export const dhcpScenario: Scenario = {
  hosts: [client, server, printer],
  linkDelayMs: 150,
  events: [
    { tMs: 0, from: client.id, to: null, build: () => buildDhcpDiscoverFrame(client, transaction) },
    {
      tMs: 600,
      from: server.id,
      to: null,
      build: () => buildDhcpOfferFrame(client, lease, transaction),
    },
    {
      tMs: 1200,
      from: client.id,
      to: null,
      build: () => buildDhcpRequestFrame(client, lease, transaction),
    },
    {
      tMs: 1800,
      from: server.id,
      to: null,
      build: () => buildDhcpAckFrame(client, lease, transaction),
    },
  ],
}
