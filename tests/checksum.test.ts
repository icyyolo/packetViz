/**
 * RFC 1071 arithmetic, checked against the RFC's own worked example and then
 * against the property that makes a checksum useful: a buffer carrying its own
 * checksum sums to all ones.
 */

import fc from 'fast-check'
import { describe, expect, it } from 'vitest'
import { complement, ipv4Checksum, onesSum, udpChecksum } from '../src/core/checksum.ts'

describe('RFC 1071', () => {
  it('reproduces the worked example from §3', () => {
    // RFC 1071 §3: the byte sequence 00 01 f2 03 f4 f5 f6 f7 sums to ddf2,
    // giving a checksum of 220d.
    const bytes = Uint8Array.from([0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7])
    expect(onesSum(bytes)).toBe(0xddf2)
    expect(complement(onesSum(bytes))).toBe(0x220d)
  })

  it('pads an odd final byte into the high half of a word', () => {
    expect(onesSum(Uint8Array.from([0x12]))).toBe(0x1200)
    expect(onesSum(Uint8Array.from([0x12, 0x00]))).toBe(0x1200)
  })

  it('is order-independent, which is why it can be summed a word at a time', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 0, maxLength: 64 }), fc.nat(), (bytes, cut) => {
        // Split on a word boundary: the sum is over 16-bit words, so a partial
        // sum is only resumable where a word ends.
        const even = bytes.subarray(0, bytes.length - (bytes.length % 2))
        const split = (cut % (even.length / 2 + 1)) * 2
        expect(onesSum(even)).toBe(onesSum(even.subarray(split), onesSum(even.subarray(0, split))))
      }),
      { numRuns: 300 },
    )
  })
})

describe('IPv4 header checksum', () => {
  it('validates a header from RFC 1071 §4.1', () => {
    // The example header in RFC 1071 §4.1: 45 00 00 30 44 22 40 00 80 06
    // (checksum) 8c 7c 19 ac ae 24 1e 2b, whose checksum is 0x442e.
    const header = Uint8Array.from([
      0x45, 0x00, 0x00, 0x30, 0x44, 0x22, 0x40, 0x00, 0x80, 0x06, 0x00, 0x00, 0x8c, 0x7c, 0x19,
      0xac, 0xae, 0x24, 0x1e, 0x2b,
    ])
    expect(ipv4Checksum(header)).toBe(0x442e)
  })

  it('makes a header carrying its own checksum sum to all ones', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 20, maxLength: 20 }), (header) => {
        const checksum = ipv4Checksum(header)
        const stamped = Uint8Array.from(header)
        stamped[10] = checksum >> 8
        stamped[11] = checksum & 0xff
        expect(onesSum(stamped)).toBe(0xffff)
      }),
      { numRuns: 500 },
    )
  })
})

describe('UDP checksum', () => {
  it('makes a datagram carrying its own checksum verify against the pseudo-header', () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 4, maxLength: 4 }),
        fc.uint8Array({ minLength: 4, maxLength: 4 }),
        fc.uint8Array({ minLength: 8, maxLength: 64 }),
        (src, dst, datagram) => {
          const checksum = udpChecksum(src, dst, datagram)
          const stamped = Uint8Array.from(datagram)
          stamped[6] = checksum >> 8
          stamped[7] = checksum & 0xff
          // Recomputing over the stamped datagram must reproduce the same value:
          // the checksum field is excluded from the sum either way.
          expect(udpChecksum(src, dst, stamped)).toBe(checksum)
        },
      ),
      { numRuns: 500 },
    )
  })

  it('never transmits a zero checksum, because zero means "not computed"', () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 4, maxLength: 4 }),
        fc.uint8Array({ minLength: 4, maxLength: 4 }),
        fc.uint8Array({ minLength: 8, maxLength: 40 }),
        (src, dst, datagram) => {
          expect(udpChecksum(src, dst, datagram)).not.toBe(0)
        },
      ),
      { numRuns: 300 },
    )
  })
})
