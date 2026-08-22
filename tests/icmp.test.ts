/**
 * ICMP is eight bytes and a checksum, so the interesting assertions are about
 * the two things it does NOT have: a length field, and any way to reach a
 * program on the other host except by having its identifier echoed back.
 */

import { describe, expect, it } from 'vitest'
import { findField, leafFields } from '../src/core/field.ts'
import { icmpChecksum } from '../src/core/checksum.ts'
import { ETH_HEADER_BYTES } from '../src/core/protocols/ethernet.ts'
import { IPV4_HEADER_BYTES } from '../src/core/protocols/ipv4.ts'
import {
  ECHO_PAYLOAD,
  ICMP_HEADER_BYTES,
  ICMP_TYPE,
  buildIcmpEchoReplyFrame,
  buildIcmpEchoRequestFrame,
  decodeIcmp,
  encodeIcmpEcho,
} from '../src/core/protocols/icmp.ts'
import { decodeFrame } from '../src/core/registry.ts'
import { toHex } from './util.ts'

const LAPTOP = { mac: 'aa:bb:cc:00:00:05', ip: '10.0.0.50' }
const SERVER = { mac: 'aa:bb:cc:00:00:09', ip: '10.0.0.9' }
const ECHO = { identifier: 0x1a2b, sequence: 1 }
const ICMP_OFFSET = ETH_HEADER_BYTES + IPV4_HEADER_BYTES

describe('ICMP echo', () => {
  it('encodes a header a byte at a time', () => {
    const message = encodeIcmpEcho({
      type: ICMP_TYPE.ECHO_REQUEST,
      identifier: 0x1a2b,
      sequence: 7,
      payload: Uint8Array.from([0xde, 0xad]),
    })

    expect(message).toHaveLength(ICMP_HEADER_BYTES + 2)
    expect(message[0]).toBe(8) // type: echo request
    expect(message[1]).toBe(0) // code: echo has no sub-types
    expect(toHex(message.subarray(4, 8))).toBe('1a2b0007')
    // `icmpChecksum` reads the checksum field as zero wherever it is asked to
    // compute one, so recomputing over the finished bytes reproduces the value
    // that was stamped into them.
    const stored = ((message[2] ?? 0) << 8) | (message[3] ?? 0)
    expect(icmpChecksum(message)).toBe(stored)
  })

  it('finds the fields at their RFC offsets', () => {
    const packet = decodeFrame(buildIcmpEchoRequestFrame(LAPTOP, SERVER, ECHO))
    expect(packet.problems).toEqual([])
    expect(packet.summary).toBe('Echo (ping) request id=0x1a2b, seq=1')

    expect(findField(packet.tree, 'icmp.type')?.byteStart).toBe(ICMP_OFFSET)
    expect(findField(packet.tree, 'icmp.ident')?.byteStart).toBe(ICMP_OFFSET + 4)
    expect(findField(packet.tree, 'icmp.seq')?.byteStart).toBe(ICMP_OFFSET + 6)
    expect(findField(packet.tree, 'icmp.data')?.byteLength).toBe(ECHO_PAYLOAD.length)
    expect(findField(packet.tree, 'icmp.checksum')?.value).toContain('[correct]')
  })

  /**
   * RFC 792: "the data received in the echo message must be returned in the echo
   * reply message". A reply that changed the data would still ping fine and
   * would still be wrong, so this is asserted rather than assumed.
   */
  it('returns the identifier, the sequence number and every byte of data unchanged', () => {
    const request = buildIcmpEchoRequestFrame(LAPTOP, SERVER, ECHO)
    const reply = buildIcmpEchoReplyFrame(SERVER, LAPTOP, ECHO)

    const requestData = findField(decodeFrame(request).tree, 'icmp.data')
    const replyData = findField(decodeFrame(reply).tree, 'icmp.data')
    expect(toHex(replyData!.raw)).toBe(toHex(requestData!.raw))

    for (const id of ['icmp.ident', 'icmp.seq']) {
      expect(toHex(findField(decodeFrame(reply).tree, id)!.raw)).toBe(
        toHex(findField(decodeFrame(request).tree, id)!.raw),
      )
    }
    expect(findField(decodeFrame(reply).tree, 'icmp.type')?.valueName).toBe('Echo (ping) reply')
  })

  /**
   * The point of `context.length`. ICMP has no length field, so a decoder that
   * assumed "the rest of the frame" would checksum Ethernet's padding into the
   * message and report a good checksum as bad.
   */
  it('takes its length from the enclosing IPv4 header, not from the frame', () => {
    // A short echo: eight header bytes and two of data, so Ethernet pads it.
    const message = encodeIcmpEcho({
      type: ICMP_TYPE.ECHO_REQUEST,
      identifier: 1,
      sequence: 1,
      payload: Uint8Array.from([0x01, 0x02]),
    })
    const frame = new Uint8Array(60)
    frame.set(message, ICMP_OFFSET)

    const withLength = decodeIcmp(frame, ICMP_OFFSET, { length: message.length })
    expect(withLength.byteLength).toBe(message.length)
    expect(findField(withLength.nodes, 'icmp.checksum')?.value).toContain('[correct]')

    // Told nothing, it falls back to the rest of the frame — and says so by
    // reporting a checksum that does not match, rather than by pretending.
    const withoutLength = decodeIcmp(frame, ICMP_OFFSET)
    expect(withoutLength.byteLength).toBeGreaterThan(message.length)
  })

  it('explains every field it emits', () => {
    for (const node of leafFields(decodeFrame(buildIcmpEchoRequestFrame(LAPTOP, SERVER, ECHO)).tree)) {
      expect(node.description, node.id).toBeTruthy()
      expect(node.reference, node.id).toBeTruthy()
    }
  })

  it('reports a message truncated inside its own header instead of reading past it', () => {
    const frame = buildIcmpEchoRequestFrame(LAPTOP, SERVER, ECHO)
    const cut = frame.subarray(0, ICMP_OFFSET + 3)

    // Asked directly, ICMP names the field that did not fit.
    const result = decodeIcmp(cut, ICMP_OFFSET, { length: 40 })
    expect(result.summary).toContain('truncated')
    expect(result.problems[0]?.message).toContain('Truncated at')
    for (const node of leafFields(result.nodes)) {
      expect(node.byteStart + node.byteLength).toBeLessThanOrEqual(cut.length)
    }

    // Through the whole stack, IPv4 catches it first — its total length says 60
    // bytes and only 43 arrived — and the dispatch stops rather than decoding a
    // payload at an offset it can no longer trust.
    const packet = decodeFrame(cut)
    expect(packet.problems.some((problem) => problem.severity === 'error')).toBe(true)
    expect(packet.problems[0]?.message).toContain('Total length claims')
  })
})
