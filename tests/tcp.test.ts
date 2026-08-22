/**
 * TCP's fixed header is easy; what needs testing is everything that is not
 * fixed. The data offset decides where the options end and the payload begins,
 * the flags are ten fields inside two bytes, and the sequence arithmetic of a
 * handshake is a claim about packets rather than about one packet.
 */

import { describe, expect, it } from 'vitest'
import { findField, leafFields, walkFields } from '../src/core/field.ts'
import { ETH_HEADER_BYTES } from '../src/core/protocols/ethernet.ts'
import { IPV4_HEADER_BYTES } from '../src/core/protocols/ipv4.ts'
import {
  TCP_FLAG,
  TCP_HEADER_BYTES,
  TCP_OPTION,
  buildTcpAckFrame,
  buildTcpSynAckFrame,
  buildTcpSynFrame,
  decodeTcp,
  encodeTcp,
  optionMss,
} from '../src/core/protocols/tcp.ts'
import { decodeFrame } from '../src/core/registry.ts'
import { toHex } from './util.ts'

const CLIENT = { mac: 'aa:bb:cc:00:00:05', ip: '10.0.0.50' }
const SERVER = { mac: 'aa:bb:cc:00:00:09', ip: '10.0.0.9' }
const CLIENT_PICK = { ephemeral: 52341, sequence: 0x1f2e3d4c }
const SERVER_PICK = { sequence: 0xa1b2c3d4 }
const TCP_OFFSET = ETH_HEADER_BYTES + IPV4_HEADER_BYTES

const num = (packet: { tree: ReturnType<typeof decodeFrame>['tree'] }, id: string): number =>
  findField(packet.tree, id)!.raw.reduce((sum, byte) => sum * 256 + byte, 0)

describe('TCP header', () => {
  it('packs the data offset and the flags into the same two bytes', () => {
    const segment = encodeTcp({
      srcPort: 1234,
      dstPort: 80,
      seq: 1,
      ack: 2,
      flags: TCP_FLAG.SYN | TCP_FLAG.ACK,
      window: 64240,
      options: [],
      payload: new Uint8Array(0),
      srcIp: CLIENT.ip,
      dstIp: SERVER.ip,
    })

    expect(segment).toHaveLength(TCP_HEADER_BYTES)
    // 0x5012: five words of header, SYN and ACK set.
    expect(toHex(segment.subarray(12, 14))).toBe('5012')
  })

  it('pads its options out to a whole number of 32-bit words', () => {
    // Three bytes of options cannot be described by a data offset, so the
    // encoder fills the fourth with a No-Operation byte.
    const segment = encodeTcp({
      srcPort: 1234,
      dstPort: 80,
      seq: 0,
      ack: 0,
      flags: TCP_FLAG.SYN,
      window: 1,
      options: [{ kind: TCP_OPTION.MSS, value: optionMss(1460) }],
      payload: new Uint8Array(0),
      srcIp: CLIENT.ip,
      dstIp: SERVER.ip,
    })

    expect(segment).toHaveLength(TCP_HEADER_BYTES + 4)
    expect(segment[12]! >> 4).toBe(6) // six words
    expect(toHex(segment.subarray(20, 24))).toBe('020405b4')
  })

  it('decodes each flag as its own field', () => {
    const packet = decodeFrame(buildTcpSynAckFrame(SERVER, CLIENT, SERVER_PICK, CLIENT_PICK))
    expect(packet.problems).toEqual([])

    expect(findField(packet.tree, 'tcp.flags.syn')?.value).toBe('Set')
    expect(findField(packet.tree, 'tcp.flags.ack')?.value).toBe('Set')
    expect(findField(packet.tree, 'tcp.flags.fin')?.value).toBe('Not set')
    // Ten fields inside two bytes: every one of them highlights those bytes.
    const flags = Array.from(walkFields(packet.tree)).filter((node) =>
      node.id.startsWith('tcp.flags.'),
    )
    expect(flags).toHaveLength(10)
    for (const flag of flags) {
      expect(flag.byteStart, flag.id).toBeGreaterThanOrEqual(TCP_OFFSET + 12)
      expect(flag.byteStart + flag.byteLength, flag.id).toBeLessThanOrEqual(TCP_OFFSET + 14)
    }
  })

  it('reads the options a SYN carries, including the ones with no value', () => {
    const packet = decodeFrame(buildTcpSynFrame(CLIENT, SERVER, CLIENT_PICK))

    expect(findField(packet.tree, 'tcp.opt.2')?.value).toBe('1460 bytes')
    expect(findField(packet.tree, 'tcp.opt.3')?.value).toContain('shift 7')
    expect(findField(packet.tree, 'tcp.opt.4')?.value).toBe('permitted')
    // SACK-permitted is a two-byte option: kind and length, and nothing else.
    expect(findField(packet.tree, 'tcp.opt.4')?.byteLength).toBe(2)
    expect(findField(packet.tree, 'tcp.opt.4.value')).toBeUndefined()
    // ...and the length byte counts the whole option, not just its value.
    expect(findField(packet.tree, 'tcp.opt.2.len')?.value).toContain('4 bytes')
  })

  /**
   * The claim the whole lesson rests on: a SYN carries no data but still
   * consumes a sequence number, so the answer acknowledges ISN + 1. It is a fact
   * about two packets, so it is asserted across two packets — and read out of
   * their bytes, not out of the scenario.
   */
  it('acknowledges one more than the sequence number a SYN announced', () => {
    const syn = decodeFrame(buildTcpSynFrame(CLIENT, SERVER, CLIENT_PICK))
    const synAck = decodeFrame(buildTcpSynAckFrame(SERVER, CLIENT, SERVER_PICK, CLIENT_PICK))
    const ack = decodeFrame(buildTcpAckFrame(CLIENT, SERVER, CLIENT_PICK, SERVER_PICK))

    expect(num(synAck, 'tcp.ack')).toBe(num(syn, 'tcp.seq') + 1)
    expect(num(ack, 'tcp.ack')).toBe(num(synAck, 'tcp.seq') + 1)
    expect(num(ack, 'tcp.seq')).toBe(num(syn, 'tcp.seq') + 1)

    // Only the first segment has the ACK flag clear.
    expect(findField(syn.tree, 'tcp.flags.ack')?.value).toBe('Not set')
    expect(findField(synAck.tree, 'tcp.flags.ack')?.value).toBe('Set')
    expect(findField(ack.tree, 'tcp.flags.ack')?.value).toBe('Set')
  })

  it('verifies a checksum that covers addresses TCP cannot see', () => {
    const packet = decodeFrame(buildTcpSynFrame(CLIENT, SERVER, CLIENT_PICK))
    expect(findField(packet.tree, 'tcp.checksum')?.value).toContain('[correct]')

    // Handed the segment with no idea what carried it, the decoder says so
    // rather than claiming the checksum is fine.
    const frame = buildTcpSynFrame(CLIENT, SERVER, CLIENT_PICK)
    const alone = decodeTcp(frame, TCP_OFFSET, { length: frame.length - TCP_OFFSET })
    expect(findField(alone.nodes, 'tcp.checksum')?.value).toContain('unverified')
  })

  it('refuses a data offset that is shorter than the fixed header', () => {
    const frame = Uint8Array.from(buildTcpSynFrame(CLIENT, SERVER, CLIENT_PICK))
    frame[TCP_OFFSET + 12] = 0x40 // four words: one short of the minimum
    const packet = decodeFrame(frame)

    const problem = packet.problems.find((candidate) => candidate.severity === 'error')
    expect(problem?.message).toContain('below the minimum')
    expect(problem?.byteStart).toBe(TCP_OFFSET + 12)
  })

  it('explains every field it emits', () => {
    for (const node of leafFields(decodeFrame(buildTcpSynFrame(CLIENT, SERVER, CLIENT_PICK)).tree)) {
      expect(node.description, node.id).toBeTruthy()
      expect(node.reference, node.id).toBeTruthy()
    }
  })
})
