/**
 * The decoder totality contract, enforced against hostile input.
 *
 * `decodeFrame` must, for ANY Uint8Array:
 *   1. never throw;
 *   2. never loop forever;
 *   3. never allocate unbounded;
 *   4. never read out of bounds.
 *
 * Phase 7 imports .pcap files this project did not create and Phase 3.5 lets a
 * user type arbitrary hex into a byte cell, so these are load-bearing.
 *
 * On clause 2: nothing in the Phase 1 decoders loops over untrusted data — the
 * spec runner walks a fixed table. The elapsed-time assertion below catches
 * "slow but terminating"; a true hang is caught by the per-test timeout, which
 * is set explicitly rather than left at the default.
 */

import fc from 'fast-check'
import { describe, expect, it } from 'vitest'
import { walkFields, type DecodedPacket } from '../src/core/field.ts'
import { decodeFrame } from '../src/core/registry.ts'
import { ARP_OPCODE, encodeArp } from '../src/core/protocols/arp.ts'
import { BROADCAST_MAC, ETHER_TYPE, encodeEthernet } from '../src/core/protocols/ethernet.ts'
import { buildDhcpAckFrame } from '../src/core/protocols/dhcp.ts'
import { buildDnsResponseFrame } from '../src/core/protocols/dns.ts'
import { buildIcmpEchoRequestFrame } from '../src/core/protocols/icmp.ts'
import { buildTcpSynFrame } from '../src/core/protocols/tcp.ts'
import { ETH_HEADER_BYTES } from '../src/core/protocols/ethernet.ts'
import { IPV4_HEADER_BYTES } from '../src/core/protocols/ipv4.ts'
import { UDP_HEADER_BYTES } from '../src/core/protocols/udp.ts'

const TIMEOUT_MS = 30_000
const PER_CASE_BUDGET_MS = 100

const VALID_FRAME = encodeEthernet({
  dst: BROADCAST_MAC,
  src: 'aa:bb:cc:00:00:01',
  etherType: ETHER_TYPE.ARP,
  payload: encodeArp({
    opcode: ARP_OPCODE.REQUEST,
    senderMac: 'aa:bb:cc:00:00:01',
    senderIp: '10.0.0.1',
    targetMac: '00:00:00:00:00:00',
    targetIp: '10.0.0.2',
  }),
})

/**
 * The other seed: a full Ethernet/IPv4/UDP/DHCP stack, which is where the
 * untrusted numbers live — two header lengths, two total lengths and an option
 * list walked one TLV at a time.
 */
const VALID_DHCP_FRAME = buildDhcpAckFrame(
  { mac: '00:11:22:33:44:55' },
  {
    serverMac: 'aa:bb:cc:00:00:01',
    serverIp: '10.0.0.1',
    clientIp: '10.0.0.50',
    subnetMask: '255.255.255.0',
    router: '10.0.0.1',
    dns: '10.0.0.1',
    leaseSeconds: 86400,
  },
  0x3903f326,
)

/**
 * Phase 9's seeds. Each brings an untrusted number the earlier ones did not: a
 * message with no length field of its own (ICMP), a header length that decides
 * where the options stop (TCP), and a name that can point anywhere in the
 * message including at itself (DNS).
 */
const VALID_ICMP_FRAME = buildIcmpEchoRequestFrame(
  { mac: 'aa:bb:cc:00:00:05', ip: '10.0.0.50' },
  { mac: 'aa:bb:cc:00:00:09', ip: '10.0.0.9' },
  { identifier: 0x1a2b, sequence: 1 },
)

const VALID_TCP_FRAME = buildTcpSynFrame(
  { mac: 'aa:bb:cc:00:00:05', ip: '10.0.0.50' },
  { mac: 'aa:bb:cc:00:00:09', ip: '10.0.0.9' },
  { ephemeral: 52341, sequence: 0x1f2e3d4c },
)

const VALID_DNS_FRAME = buildDnsResponseFrame(
  { mac: 'aa:bb:cc:00:00:01', ip: '10.0.0.1' },
  { mac: 'aa:bb:cc:00:00:05', ip: '10.0.0.50' },
  { ephemeral: 41234, id: 0x1a2b },
  'files.corp.internal',
  { address: '10.0.0.9', ttl: 300 },
)

/** Offsets into `VALID_DHCP_FRAME`, so the named cases below read as what they are. */
const IP_AT = ETH_HEADER_BYTES
const UDP_AT = IP_AT + IPV4_HEADER_BYTES
const DHCP_AT = UDP_AT + UDP_HEADER_BYTES
/** First option byte: the fixed BOOTP header is 240 bytes including the cookie. */
const OPTIONS_AT = DHCP_AT + 240

/** A copy of a frame with one or more bytes overwritten. */
function patched(seed: Uint8Array, patch: Record<number, number>): Uint8Array {
  const frame = Uint8Array.from(seed)
  for (const [offset, value] of Object.entries(patch)) frame[Number(offset)] = value
  return frame
}

/** A copy of the DHCP frame with one or more bytes overwritten. */
function withBytes(patch: Record<number, number>): Uint8Array {
  return patched(VALID_DHCP_FRAME, patch)
}

/** Where each Phase 9 protocol's own header starts in its seed frame. */
const TCP_AT = ETH_HEADER_BYTES + IPV4_HEADER_BYTES
const DNS_AT = ETH_HEADER_BYTES + IPV4_HEADER_BYTES + UDP_HEADER_BYTES

/** Runs the decoder and asserts all four clauses. Returns nothing; it throws on violation. */
function checkContract(frame: Uint8Array): void {
  const started = performance.now()
  // Clause 1: an exception here fails the property and fast-check prints the frame.
  const packet: DecodedPacket = decodeFrame(frame)
  const elapsed = performance.now() - started

  // Clause 2 (weak form): terminating, and not pathologically slow.
  expect(elapsed).toBeLessThan(PER_CASE_BUDGET_MS)

  let nodeCount = 0
  for (const node of walkFields(packet.tree)) {
    nodeCount += 1

    // Clause 4: every span lies inside the frame.
    expect(node.byteStart).toBeGreaterThanOrEqual(0)
    expect(node.byteLength).toBeGreaterThanOrEqual(0)
    expect(node.byteStart + node.byteLength).toBeLessThanOrEqual(frame.length)
    expect(node.raw.length).toBe(node.byteLength)

    // Clause 3: raw is a VIEW of the caller's buffer, so the decoder cannot have
    // sized an allocation from an untrusted length field.
    expect(node.raw.buffer).toBe(frame.buffer)
    expect(node.raw.byteOffset).toBe(frame.byteOffset + node.byteStart)

    if (node.bitLength !== undefined) {
      expect(node.bitOffset ?? 0).toBeLessThan(8)
      expect((node.bitOffset ?? 0) + node.bitLength).toBeLessThanOrEqual(node.byteLength * 8)
    }
  }

  // Clause 3: the tree cannot grow faster than the input it describes.
  expect(nodeCount).toBeLessThanOrEqual(64 + frame.length)

  for (const problem of packet.problems) {
    expect(problem.byteStart).toBeGreaterThanOrEqual(0)
    expect(problem.byteStart + problem.byteLength).toBeLessThanOrEqual(frame.length)
    expect(problem.message.length).toBeGreaterThan(0)
  }

  expect(packet.frame).toBe(frame)
  expect(packet.summary.length).toBeGreaterThan(0)
}

describe('decoder totality contract', () => {
  it(
    'survives arbitrary bytes',
    () => {
      fc.assert(
        fc.property(fc.uint8Array({ minLength: 0, maxLength: 200 }), checkContract),
        { numRuns: 2000 },
      )
    },
    TIMEOUT_MS,
  )

  it(
    'survives a valid frame truncated at every offset',
    () => {
      fc.assert(
        fc.property(fc.integer({ min: 0, max: VALID_FRAME.length }), (length) => {
          checkContract(VALID_FRAME.subarray(0, length))
        }),
        { numRuns: 2500 },
      )
    },
    TIMEOUT_MS,
  )

  it(
    'survives a valid frame with one byte mutated',
    () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 0, max: VALID_FRAME.length - 1 }),
          fc.integer({ min: 0, max: 255 }),
          (index, value) => {
            const mutated = Uint8Array.from(VALID_FRAME)
            mutated[index] = value
            checkContract(mutated)
          },
        ),
        { numRuns: 2500 },
      )
    },
    TIMEOUT_MS,
  )

  it(
    'survives the DHCP stack truncated at every offset',
    () => {
      fc.assert(
        fc.property(fc.integer({ min: 0, max: VALID_DHCP_FRAME.length }), (length) => {
          checkContract(VALID_DHCP_FRAME.subarray(0, length))
        }),
        // Enough that the DHCP stack, like the ARP one, clears 5,000 generated
        // cases on its own rather than borrowing the arbitrary-bytes run.
        { numRuns: 3000 },
      )
    },
    TIMEOUT_MS,
  )

  it(
    'survives the DHCP stack with one byte mutated',
    () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 0, max: VALID_DHCP_FRAME.length - 1 }),
          fc.integer({ min: 0, max: 255 }),
          (index, value) => {
            checkContract(withBytes({ [index]: value }))
          },
        ),
        { numRuns: 2500 },
      )
    },
    TIMEOUT_MS,
  )

  for (const [label, seed] of [
    ['ICMP', VALID_ICMP_FRAME],
    ['TCP', VALID_TCP_FRAME],
    ['DNS', VALID_DNS_FRAME],
  ] as const) {
    it(
      `survives the ${label} stack truncated at every offset`,
      () => {
        fc.assert(
          fc.property(fc.integer({ min: 0, max: seed.length }), (length) => {
            checkContract(seed.subarray(0, length))
          }),
          { numRuns: 2500 },
        )
      },
      TIMEOUT_MS,
    )

    it(
      `survives the ${label} stack with one byte mutated`,
      () => {
        fc.assert(
          fc.property(
            fc.integer({ min: 0, max: seed.length - 1 }),
            fc.integer({ min: 0, max: 255 }),
            (index, value) => {
              checkContract(patched(seed, { [index]: value }))
            },
          ),
          { numRuns: 2500 },
        )
      },
      TIMEOUT_MS,
    )
  }

  /**
   * Random mutation finds these eventually; naming them means a regression is
   * reported as the case it is rather than as a shrunk byte index. Each one is a
   * length field lying about something the decoder would otherwise trust.
   */
  describe('the named adversarial cases', () => {
    it('a DHCP option that declares zero length does not spin', () => {
      // Option code 100, length 0, in place of the first real option.
      checkContract(withBytes({ [OPTIONS_AT]: 100, [OPTIONS_AT + 1]: 0 }))
    })

    it('a DHCP option whose length runs past the buffer stops at the buffer', () => {
      const frame = withBytes({ [OPTIONS_AT + 1]: 0xff })
      checkContract(frame)
      const problems = decodeFrame(frame).problems
      expect(problems.some((problem) => problem.message.includes('of value but only'))).toBe(true)
    })

    it('an option list with no terminator ends with the bytes', () => {
      const frame = Uint8Array.from(VALID_DHCP_FRAME)
      frame[frame.length - 1] = 0x01 // was the End option
      checkContract(frame)
    })

    it('an IPv4 header length below the minimum is refused', () => {
      checkContract(withBytes({ [IP_AT]: 0x41 })) // version 4, IHL 1
    })

    it('an IPv4 header length longer than the frame is clamped', () => {
      checkContract(withBytes({ [IP_AT]: 0x4f })) // IHL 15 = 60 bytes of header
    })

    it('an IPv4 total length larger than the frame is refused', () => {
      checkContract(withBytes({ [IP_AT + 2]: 0xff, [IP_AT + 3]: 0xff }))
    })

    it('a UDP length larger than the frame is refused', () => {
      checkContract(withBytes({ [UDP_AT + 4]: 0xff, [UDP_AT + 5]: 0xff }))
    })

    it('a UDP length shorter than its own header is refused', () => {
      checkContract(withBytes({ [UDP_AT + 4]: 0x00, [UDP_AT + 5]: 0x01 }))
    })

    it('a DHCP message with no magic cookie is not read as options', () => {
      checkContract(withBytes({ [DHCP_AT + 236]: 0x00 }))
    })

    it('a TCP data offset below the minimum is refused', () => {
      const frame = patched(VALID_TCP_FRAME, { [TCP_AT + 12]: 0x40 }) // four words
      checkContract(frame)
      expect(decodeFrame(frame).problems.some((p) => p.message.includes('below the minimum'))).toBe(true)
    })

    it('a TCP data offset longer than the segment is clamped', () => {
      checkContract(patched(VALID_TCP_FRAME, { [TCP_AT + 12]: 0xf0 })) // fifteen words
    })

    it('a TCP option that declares a length of zero does not spin', () => {
      // Kind 8 (timestamps), length 0, where the MSS option used to be.
      checkContract(patched(VALID_TCP_FRAME, { [TCP_AT + 20]: 8, [TCP_AT + 21]: 0 }))
    })

    it('a TCP option whose length runs past the header stops at the header', () => {
      checkContract(patched(VALID_TCP_FRAME, { [TCP_AT + 21]: 0xff }))
    })

    /**
     * The case DNS exists in this suite for. A name that points at itself is a
     * loop the wire format permits, and nothing but the decoder stops it.
     */
    it('a DNS name pointing at itself does not spin', () => {
      // The question's name starts at DNS_AT + 12; make it a pointer to itself.
      const frame = patched(VALID_DNS_FRAME, { [DNS_AT + 12]: 0xc0, [DNS_AT + 13]: 0x0c })
      checkContract(frame)
      expect(decodeFrame(frame).problems.some((p) => p.message.includes('already visited'))).toBe(true)
    })

    it('a DNS name pointing outside the message is refused', () => {
      checkContract(patched(VALID_DNS_FRAME, { [DNS_AT + 12]: 0xc3, [DNS_AT + 13]: 0xff }))
    })

    it('a DNS question count larger than the message stops at the message', () => {
      const frame = patched(VALID_DNS_FRAME, { [DNS_AT + 4]: 0xff, [DNS_AT + 5]: 0xff })
      checkContract(frame)
      // Reported once, not once per section: with the questions unparsed we do
      // not know where the answers begin, so we do not guess.
      const named = decodeFrame(frame).problems.filter((p) => p.message.startsWith('DNS name'))
      expect(named).toHaveLength(1)
    })

    it('a DNS answer count larger than the message stops at the message', () => {
      checkContract(patched(VALID_DNS_FRAME, { [DNS_AT + 6]: 0xff, [DNS_AT + 7]: 0xff }))
    })

    it('a DNS record data length larger than the message is refused', () => {
      // Header (12), the question's name (21) and its type and class (4), then
      // the answer's compressed name (2), type, class and TTL (8).
      const rdLength = DNS_AT + 12 + 21 + 4 + 10
      const frame = patched(VALID_DNS_FRAME, { [rdLength]: 0xff, [rdLength + 1]: 0xff })
      checkContract(frame)
      expect(
        decodeFrame(frame).problems.some((p) => p.message.includes('runs past the end of the message')),
      ).toBe(true)
    })

    it('an ICMP message shorter than its own header is refused', () => {
      // IPv4 total length cut to the header plus three bytes.
      checkContract(patched(VALID_ICMP_FRAME, { [ETH_HEADER_BYTES + 2]: 0x00, [ETH_HEADER_BYTES + 3]: 0x17 }))
    })
  })

  it('survives the empty frame and a single byte', () => {
    checkContract(new Uint8Array(0))
    checkContract(new Uint8Array([0xff]))
  })

  it('never reports a problem without a byte span the hex view can highlight', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 0, maxLength: 64 }), (frame) => {
        for (const problem of decodeFrame(frame).problems) {
          expect(Number.isInteger(problem.byteStart)).toBe(true)
          expect(Number.isInteger(problem.byteLength)).toBe(true)
        }
      }),
      { numRuns: 500 },
    )
  })
})
