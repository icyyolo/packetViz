/**
 * The registry has to be able to describe itself honestly, because Phase 8's
 * concept map and reference pages are drawn from that description. A map that
 * advertises a protocol nobody wrote is worse than no map.
 */

import { describe, expect, it } from 'vitest'
import {
  BY_UDP_PORT,
  describeProtocols,
  findProtocol,
  type ProtocolEntry,
} from '../src/core/registry.ts'
import { DHCP_CLIENT_PORT, DHCP_SERVER_PORT } from '../src/core/protocols/dhcp.ts'

describe('the describable registry', () => {
  it('reports exactly the protocols that have a decoder', () => {
    const implemented = describeProtocols()
      .filter((protocol) => protocol.implemented)
      .map((protocol) => protocol.id)

    expect(implemented).toEqual(['eth', 'arp', 'ip', 'udp', 'dhcp'])
  })

  it('names the protocols it does not implement, rather than hiding them', () => {
    const missing = describeProtocols()
      .filter((protocol) => !protocol.implemented)
      .map((protocol) => protocol.id)

    expect(missing).toEqual(['icmp', 'tcp', 'dns'])
  })

  it('derives the encapsulation edges, including edges to unimplemented protocols', () => {
    expect(findProtocol('eth')?.encapsulates).toEqual(['arp', 'ip'])
    expect(findProtocol('ip')?.encapsulates).toEqual(['icmp', 'tcp', 'udp'])
    expect(findProtocol('udp')?.encapsulates).toEqual(['dhcp', 'dns'])
    expect(findProtocol('dhcp')?.encapsulates).toEqual([])
  })

  it('carries the spec table for every implemented protocol, and none for the rest', () => {
    for (const protocol of describeProtocols()) {
      expect(protocol.specs.length > 0, protocol.id).toBe(protocol.implemented)
    }
  })

  it('gives every protocol a blurb and an RFC, implemented or not', () => {
    for (const protocol of describeProtocols()) {
      expect(protocol.blurb.length, protocol.id).toBeGreaterThan(20)
      expect(protocol.reference, protocol.id).toMatch(/^RFC \d+$/)
    }
  })

  /**
   * Plan step 8.2's check, run as a test rather than by hand: unregister DHCP
   * and the description has to follow, with no other edit anywhere. If this ever
   * passes while the map still shows DHCP as implemented, the map has grown its
   * own copy of the truth.
   */
  it('stops reporting a protocol as implemented the moment its decoder is unregistered', () => {
    const table = BY_UDP_PORT as Map<number, ProtocolEntry>
    const entry = table.get(DHCP_SERVER_PORT)!
    table.delete(DHCP_SERVER_PORT)
    table.delete(DHCP_CLIENT_PORT)

    try {
      const dhcp = findProtocol('dhcp')
      expect(dhcp?.implemented).toBe(false)
      expect(dhcp?.specs).toEqual([])
      // Still on the map, still named, just no longer claimed.
      expect(describeProtocols().map((protocol) => protocol.id)).toContain('dhcp')
    } finally {
      table.set(DHCP_SERVER_PORT, entry)
      table.set(DHCP_CLIENT_PORT, entry)
    }

    expect(findProtocol('dhcp')?.implemented).toBe(true)
  })
})
