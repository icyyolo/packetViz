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
        { numRuns: 1500 },
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
        { numRuns: 1500 },
      )
    },
    TIMEOUT_MS,
  )

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
