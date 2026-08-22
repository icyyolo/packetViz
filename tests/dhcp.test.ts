/**
 * DHCP: a fixed 240-byte header the spec runner handles, and an option list it
 * cannot. The option loop is the only place in this codebase where the decoder
 * walks untrusted data, so half of this file is about malformed option lists.
 */

import { describe, expect, it } from 'vitest'
import { findField, leafFields } from '../src/core/field.ts'
import {
  DHCP_FIXED_BYTES,
  DHCP_MESSAGE_TYPE,
  DHCP_OPTION,
  DHCP_OP,
  buildDhcpAckFrame,
  buildDhcpDiscoverFrame,
  buildDhcpOfferFrame,
  buildDhcpRequestFrame,
  decodeDhcp,
  encodeDhcp,
  optionCodes,
  optionIpv4,
  optionU32,
  optionU8,
} from '../src/core/protocols/dhcp.ts'
import { ETH_HEADER_BYTES } from '../src/core/protocols/ethernet.ts'
import { IPV4_HEADER_BYTES } from '../src/core/protocols/ipv4.ts'
import { UDP_HEADER_BYTES } from '../src/core/protocols/udp.ts'
import { decodeFrame } from '../src/core/registry.ts'

const CLIENT = { mac: '00:11:22:33:44:55' }
const LEASE = {
  serverMac: 'aa:bb:cc:00:00:01',
  serverIp: '10.0.0.1',
  clientIp: '10.0.0.50',
  subnetMask: '255.255.255.0',
  router: '10.0.0.1',
  dns: '10.0.0.1',
  leaseSeconds: 86400,
}
const XID = 0x3903f326

/** Where DHCP starts inside a frame: Ethernet, then IPv4, then UDP. */
const DHCP_OFFSET = ETH_HEADER_BYTES + IPV4_HEADER_BYTES + UDP_HEADER_BYTES

function bare(options: { code: number; value: Uint8Array }[]): Uint8Array {
  return encodeDhcp({
    op: DHCP_OP.REQUEST,
    xid: XID,
    secs: 0,
    broadcast: true,
    clientIp: '0.0.0.0',
    yourIp: '0.0.0.0',
    serverIp: '0.0.0.0',
    relayIp: '0.0.0.0',
    clientMac: CLIENT.mac,
    options,
  })
}

describe('the BOOTP fixed header', () => {
  it('puts the magic cookie at offset 236, where RFC 2131 says it is', () => {
    const packet = decodeFrame(buildDhcpDiscoverFrame(CLIENT, XID))
    const cookie = findField(packet.tree, 'dhcp.cookie')

    expect(DHCP_FIXED_BYTES).toBe(240)
    expect(cookie?.byteStart).toBe(DHCP_OFFSET + 236)
    expect(cookie?.value).toBe('0x63825363')
    expect(packet.problems).toEqual([])
  })

  it('is 236 bytes of which 192 are two string fields nobody fills in', () => {
    const packet = decodeFrame(buildDhcpDiscoverFrame(CLIENT, XID))
    expect(findField(packet.tree, 'dhcp.server')?.byteLength).toBe(64)
    expect(findField(packet.tree, 'dhcp.file')?.byteLength).toBe(128)
    expect(findField(packet.tree, 'dhcp.server')?.value).toBe('(empty)')
  })

  it('rejects bytes whose cookie is missing rather than reading them as options', () => {
    const frame = Uint8Array.from(buildDhcpDiscoverFrame(CLIENT, XID))
    frame[DHCP_OFFSET + 236] = (frame[DHCP_OFFSET + 236] ?? 0) ^ 0xff

    const packet = decodeFrame(frame)
    expect(packet.problems.some((problem) => problem.message.includes('not DHCP options'))).toBe(true)
    expect(findField(packet.tree, 'dhcp.opt.53')).toBeUndefined()
  })
})

describe('DHCP options', () => {
  it('decodes option 53 as the message type', () => {
    const packet = decodeFrame(buildDhcpDiscoverFrame(CLIENT, XID))
    expect(findField(packet.tree, 'dhcp.opt.53.value')?.value).toBe('1 (DISCOVER)')
    expect(packet.summary).toBe('DHCP DISCOVER')
  })

  it('gives every option a code, a length and a value, each with its own bytes', () => {
    const packet = decodeFrame(buildDhcpAckFrame(CLIENT, LEASE, XID))
    const lease = findField(packet.tree, 'dhcp.opt.51')

    expect(lease?.byteLength).toBe(6) // code + length + four bytes of seconds
    expect(lease?.children?.map((child) => child.byteLength)).toEqual([1, 1, 4])
    expect(findField(packet.tree, 'dhcp.opt.51.value')?.value).toBe('86400 seconds')
    expect(findField(packet.tree, 'dhcp.opt.1.value')?.value).toBe('255.255.255.0')
    expect(findField(packet.tree, 'dhcp.opt.55')).toBeUndefined() // not in an ACK
  })

  it('names the codes inside a parameter request list', () => {
    const packet = decodeFrame(buildDhcpDiscoverFrame(CLIENT, XID))
    expect(findField(packet.tree, 'dhcp.opt.55.value')?.value).toBe(
      '1 (Subnet mask), 3 (Router), 6 (Domain name server)',
    )
  })

  it('shows an unknown option as raw bytes instead of giving up on the packet', () => {
    const message = bare([
      { code: DHCP_OPTION.MESSAGE_TYPE, value: optionU8(DHCP_MESSAGE_TYPE.DISCOVER) },
      { code: 200, value: Uint8Array.from([0xca, 0xfe]) },
    ])
    const decoded = decodeDhcp(message, 0)

    expect(decoded.problems).toEqual([])
    expect(findField(decoded.nodes, 'dhcp.opt.200')?.value).toBe('ca fe')
    expect(decoded.messageType).toBe(DHCP_MESSAGE_TYPE.DISCOVER)
  })

  it('stops at an option whose length runs past the buffer, and says which one', () => {
    const message = Uint8Array.from(
      bare([{ code: DHCP_OPTION.SERVER_ID, value: optionIpv4('10.0.0.1') }]),
    )
    // The server-identifier option sits right after the cookie: claim 40 bytes.
    message[DHCP_FIXED_BYTES + 1] = 40

    const decoded = decodeDhcp(message, 0)
    expect(decoded.problems).toHaveLength(1)
    expect(decoded.problems[0]?.message).toContain('declares 40 byte(s) of value but only')
    for (const problem of decoded.problems) {
      expect(problem.byteStart + problem.byteLength).toBeLessThanOrEqual(message.length)
    }
  })

  it('terminates on a zero-length option instead of spinning on it', () => {
    const message = bare([
      { code: DHCP_OPTION.MESSAGE_TYPE, value: optionU8(DHCP_MESSAGE_TYPE.DISCOVER) },
      { code: 100, value: new Uint8Array(0) },
      { code: DHCP_OPTION.REQUESTED_IP, value: optionIpv4('10.0.0.50') },
    ])
    const started = performance.now()
    const decoded = decodeDhcp(message, 0)

    expect(performance.now() - started).toBeLessThan(100)
    expect(findField(decoded.nodes, 'dhcp.opt.100')?.byteLength).toBe(2)
    // The loop moved on: the option after the empty one is still decoded.
    expect(findField(decoded.nodes, 'dhcp.opt.50.value')?.value).toBe('10.0.0.50')
  })

  it('stops at the end of the buffer when the option list has no terminator', () => {
    const full = bare([{ code: DHCP_OPTION.MESSAGE_TYPE, value: optionU8(1) }])
    const truncated = full.subarray(0, full.length - 1) // drop the End option

    const decoded = decodeDhcp(truncated, 0)
    expect(decoded.problems).toEqual([])
    expect(findField(decoded.nodes, 'dhcp.opt.255')).toBeUndefined()
    expect(decoded.messageType).toBe(1)
  })

  it('keeps every option node inside the buffer it came from', () => {
    const message = bare([
      { code: DHCP_OPTION.MESSAGE_TYPE, value: optionU8(3) },
      { code: DHCP_OPTION.PARAMETER_REQUEST_LIST, value: optionCodes([1, 3, 6, 15, 51]) },
      { code: DHCP_OPTION.LEASE_TIME, value: optionU32(3600) },
    ])
    for (const node of leafFields(decodeDhcp(message, 0).nodes)) {
      expect(node.byteStart + node.byteLength).toBeLessThanOrEqual(message.length)
      expect(node.raw.buffer).toBe(message.buffer)
    }
  })
})

describe('the four messages of a DORA exchange', () => {
  const frames = [
    buildDhcpDiscoverFrame(CLIENT, XID),
    buildDhcpOfferFrame(CLIENT, LEASE, XID),
    buildDhcpRequestFrame(CLIENT, LEASE, XID),
    buildDhcpAckFrame(CLIENT, LEASE, XID),
  ]

  it('decodes to DISCOVER, OFFER, REQUEST, ACK — read from option 53, not from the builder', () => {
    expect(frames.map((frame) => decodeFrame(frame).summary)).toEqual([
      'DHCP DISCOVER',
      'DHCP OFFER',
      'DHCP REQUEST',
      'DHCP ACK',
    ])
  })

  it('produces no problems anywhere in the stack', () => {
    for (const frame of frames) expect(decodeFrame(frame).problems).toEqual([])
  })

  it('ties the exchange together with one transaction ID, which is all UDP gives it', () => {
    for (const frame of frames) {
      expect(findField(decodeFrame(frame).tree, 'dhcp.id')?.value).toBe('0x3903f326')
    }
  })

  it('offers the address in yiaddr and confirms it there too', () => {
    expect(findField(decodeFrame(frames[1]!).tree, 'dhcp.ip.your')?.value).toBe('10.0.0.50')
    expect(findField(decodeFrame(frames[3]!).tree, 'dhcp.ip.your')?.value).toBe('10.0.0.50')
    // The client does not have it yet in the request: it asks by option 50.
    expect(findField(decodeFrame(frames[2]!).tree, 'dhcp.ip.your')?.value).toBe('0.0.0.0')
    expect(findField(decodeFrame(frames[2]!).tree, 'dhcp.opt.50.value')?.value).toBe('10.0.0.50')
  })

  it('sends the client\'s messages from nowhere, to everyone', () => {
    const discover = decodeFrame(frames[0]!)
    expect(findField(discover.tree, 'ip.src')?.value).toBe('0.0.0.0')
    expect(findField(discover.tree, 'ip.dst')?.value).toBe('255.255.255.255')
    expect(findField(discover.tree, 'udp.srcport')?.value).toBe('68 (DHCP client)')
    expect(findField(discover.tree, 'udp.dstport')?.value).toBe('67 (DHCP server)')
    expect(findField(discover.tree, 'dhcp.flags')?.value).toBe('0x8000 (broadcast)')
  })
})
