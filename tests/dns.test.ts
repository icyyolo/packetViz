/**
 * DNS, and specifically name compression — the one place in this project where
 * a field's value is not a function of its own bytes.
 *
 * The pointer cases matter more than the happy path: a pointer that points at
 * itself is a loop written into a wire format, and clause 2 of the decoder
 * contract says we terminate anyway.
 */

import { describe, expect, it } from 'vitest'
import { findField, leafFields } from '../src/core/field.ts'
import { ETH_HEADER_BYTES } from '../src/core/protocols/ethernet.ts'
import { IPV4_HEADER_BYTES } from '../src/core/protocols/ipv4.ts'
import { UDP_HEADER_BYTES } from '../src/core/protocols/udp.ts'
import {
  DNS_HEADER_BYTES,
  DNS_TYPE,
  buildDnsQueryFrame,
  buildDnsResponseFrame,
  decodeDns,
  encodeName,
} from '../src/core/protocols/dns.ts'
import { decodeFrame } from '../src/core/registry.ts'
import { toHex } from './util.ts'

const LAPTOP = { mac: 'aa:bb:cc:00:00:05', ip: '10.0.0.50' }
const RESOLVER = { mac: 'aa:bb:cc:00:00:01', ip: '10.0.0.1' }
const PICK = { ephemeral: 41234, id: 0x1a2b }
const HOSTNAME = 'files.corp.internal'
const ANSWER = { address: '10.0.0.9', ttl: 300 }
const DNS_OFFSET = ETH_HEADER_BYTES + IPV4_HEADER_BYTES + UDP_HEADER_BYTES

function query(): Uint8Array {
  return buildDnsQueryFrame(LAPTOP, RESOLVER, PICK, HOSTNAME)
}

function response(): Uint8Array {
  return buildDnsResponseFrame(RESOLVER, LAPTOP, PICK, HOSTNAME, ANSWER)
}

describe('DNS names', () => {
  it('encodes a name as length-prefixed labels with no dots', () => {
    const encoded = encodeName('a.bc')
    expect(toHex(encoded)).toBe('0161026263' + '00')
    expect(encodeName('')).toEqual(Uint8Array.from([0]))
  })

  it('decodes the question back to the name that was asked', () => {
    const packet = decodeFrame(query())
    expect(packet.problems).toEqual([])
    expect(packet.summary).toBe('DNS query files.corp.internal')

    const name = findField(packet.tree, 'dns.qry.name')
    expect(name?.value).toBe(HOSTNAME)
    // 5 files 4 corp 8 internal 0 — the labels plus their length bytes.
    expect(name?.byteLength).toBe(HOSTNAME.length + 2)
    expect(name?.name).toBe('Name')
    expect(findField(packet.tree, 'dns.qry.type')?.value).toContain('host address')
  })

  it('follows a compression pointer to a name that is somewhere else', () => {
    const packet = decodeFrame(response())
    expect(packet.problems).toEqual([])

    const name = findField(packet.tree, 'dns.resp.name')
    expect(name?.byteLength).toBe(2)
    expect(toHex(name!.raw)).toBe('c00c')
    expect(name?.value).toBe(HOSTNAME)
    // The tree says so out loud, because two bytes that read as a name are
    // exactly the kind of thing a reader should be told about.
    expect(name?.name).toBe('Name (compressed)')
    expect(findField(packet.tree, 'dns.a')?.value).toBe('10.0.0.9')
    expect(findField(packet.tree, 'dns.resp.ttl')?.value).toBe('300 seconds')
  })

  it('sets the flags a stub resolver and its server actually send', () => {
    const asked = decodeFrame(query())
    expect(findField(asked.tree, 'dns.flags.response')?.value).toContain('Query')
    expect(findField(asked.tree, 'dns.flags.recdesired')?.value).toBe('1 (Set)')

    const answered = decodeFrame(response())
    expect(findField(answered.tree, 'dns.flags.response')?.value).toContain('Response')
    expect(findField(answered.tree, 'dns.flags.recavail')?.value).toBe('1 (Set)')
    expect(findField(answered.tree, 'dns.count.answers')?.value).toBe('1')
  })

  it('explains every field it emits', () => {
    for (const node of leafFields(decodeFrame(response()).tree)) {
      expect(node.description, node.id).toBeTruthy()
      expect(node.reference, node.id).toBeTruthy()
    }
  })
})

/**
 * The adversarial half. Each case is a message a decoder could be talked into
 * looping on or reading out of, built by hand because no encoder of ours would
 * ever produce one.
 */
describe('DNS names that are trying to hurt you', () => {
  /** A DNS message with a header, then whatever bytes the case needs. */
  function message(...tail: number[]): { frame: Uint8Array; length: number } {
    const header = [
      0x1a, 0x2b, // transaction id
      0x01, 0x00, // flags: recursion desired
      0x00, 0x01, // one question
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]
    const body = [...header, ...tail]
    const frame = new Uint8Array(DNS_OFFSET + body.length)
    frame.set(body, DNS_OFFSET)
    return { frame, length: body.length }
  }

  function decode(built: { frame: Uint8Array; length: number }) {
    return decodeDns(built.frame, DNS_OFFSET, { length: built.length })
  }

  it('refuses a pointer that points at itself', () => {
    // The name at offset 12 is a pointer to offset 12.
    const result = decode(message(0xc0, 0x0c))
    expect(result.problems[0]?.severity).toBe('error')
    expect(result.problems[0]?.message).toContain('already visited')
  })

  it('refuses two pointers that point at each other', () => {
    // 12: pointer to 14. 14: pointer to 12.
    const result = decode(message(0xc0, 0x0e, 0xc0, 0x0c))
    expect(result.problems[0]?.message).toContain('already visited')
  })

  it('refuses a pointer that leaves the message', () => {
    const result = decode(message(0xc3, 0xff))
    expect(result.problems[0]?.message).toContain('outside the message')
  })

  it('refuses a label whose length runs past the message', () => {
    const result = decode(message(0x40, 0x61, 0x62))
    expect(result.problems[0]?.message).toContain('reserved length bits')

    const long = decode(message(0x3f, 0x61, 0x62))
    expect(long.problems[0]?.message).toContain('the message ends at')
  })

  it('reports a question count larger than the message it arrived in', () => {
    const built = message(0x00) // one root-labelled name and then nothing
    // Claim sixteen questions in a message that holds one truncated one.
    built.frame[DNS_OFFSET + 5] = 0x10
    const result = decode(built)
    expect(result.problems.some((problem) => problem.severity === 'error')).toBe(true)
    // Whatever it managed to read stays inside the buffer.
    for (const node of leafFields(result.nodes)) {
      expect(node.byteStart + node.byteLength).toBeLessThanOrEqual(built.frame.length)
    }
  })

  it('refuses a record whose data length runs past the message', () => {
    // A complete answer record whose rdlength claims 65,535 bytes of address.
    const built = message(
      0x01, 0x61, 0x00, // name: "a"
      0x00, DNS_TYPE.A, // type A
      0x00, 0x01, // class IN
      0x00, 0x00, 0x00, 0x3c, // ttl 60
      0xff, 0xff, // data length: a lie
    )
    built.frame[DNS_OFFSET + 5] = 0x00 // no questions
    built.frame[DNS_OFFSET + 7] = 0x01 // one answer

    const result = decode(built)
    expect(result.problems[0]?.severity).toBe('error')
    expect(result.problems[0]?.message).toContain('runs past the end of the message')
    // Nothing was allocated from that number: no node claims those bytes.
    for (const node of leafFields(result.nodes)) {
      expect(node.byteStart + node.byteLength).toBeLessThanOrEqual(built.frame.length)
    }
  })

  it('reads the header even when everything after it is nonsense', () => {
    const result = decode(message(0xff, 0xff, 0xff))
    expect(findField(result.nodes, 'dns.id')?.value).toBe('0x1a2b')
    expect(result.byteLength).toBeGreaterThanOrEqual(DNS_HEADER_BYTES)
  })
})
