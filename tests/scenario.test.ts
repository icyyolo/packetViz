import { readFileSync, readdirSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { leafFields } from '../src/core/field.ts'
import { LESSONS, findLesson } from '../src/lessons/index.ts'
import { arpScenario } from '../src/lessons/arp/scenario.ts'
import { compileScenario, flightProgress, markAt } from '../src/scenario/compile.ts'

describe('compileScenario', () => {
  const timeline = compileScenario(arpScenario)

  it('compiles the ARP scenario to two decoded packets', () => {
    expect(timeline.packets).toHaveLength(2)
    expect(timeline.packets.map((packet) => packet.summary)).toEqual([
      'Who has 10.0.0.2? Tell 10.0.0.1',
      '10.0.0.2 is at aa:bb:cc:00:00:02',
    ])
    expect(timeline.packets.flatMap((packet) => packet.problems)).toEqual([])
  })

  it('derives marks from event times and the link delay', () => {
    expect(timeline.marks).toEqual([
      { packetIndex: 0, sentMs: 0, arrivedMs: 120, from: 'alice', to: null },
      { packetIndex: 1, sentMs: 500, arrivedMs: 620, from: 'bob', to: 'alice' },
    ])
    expect(timeline.durationMs).toBeGreaterThan(620)
  })

  it('reports the packet in flight as a pure function of t', () => {
    const mark = timeline.marks[0]!
    expect(flightProgress(mark, -1)).toBeNull()
    expect(flightProgress(mark, 0)).toBe(0)
    expect(flightProgress(mark, 60)).toBeCloseTo(0.5)
    expect(flightProgress(mark, 120)).toBe(1)
    expect(flightProgress(mark, 121)).toBeNull()
  })

  it('reports which packet has most recently been sent', () => {
    expect(markAt(timeline.marks, -1)).toBe(-1)
    expect(markAt(timeline.marks, 0)).toBe(0)
    expect(markAt(timeline.marks, 499)).toBe(0)
    expect(markAt(timeline.marks, 500)).toBe(1)
  })
})

describe('lesson registry', () => {
  it('resolves known slugs and refuses unknown ones', () => {
    expect(findLesson('arp')?.title).toContain('ARP')
    expect(findLesson('nope')).toBeUndefined()
    expect(findLesson(undefined)).toBeUndefined()
  })

  it('gives every lesson a unique slug, a title, a blurb and a filename', () => {
    const slugs = LESSONS.map((lesson) => lesson.slug)
    expect(new Set(slugs).size).toBe(slugs.length)
    for (const lesson of LESSONS) {
      expect(lesson.title.length).toBeGreaterThan(0)
      expect(lesson.blurb.length).toBeGreaterThan(0)
      expect(lesson.filename).toMatch(/\.pcap$/)
    }
  })

  it('narrates every packet it compiles', () => {
    for (const lesson of LESSONS) {
      const compiled = compileScenario(lesson.scenario)
      expect(lesson.narration.steps).toHaveLength(compiled.packets.length)
      for (const step of lesson.narration.steps) {
        expect(step.title.length).toBeGreaterThan(0)
        expect(step.body.length).toBeGreaterThan(0)
      }
    }
  })
})

/**
 * Lesson criterion #7: no protocol field value may appear in a lesson. Only host
 * addresses, timings and prose belong there. Comments are stripped first — the
 * scenario's own header comment names the things it deliberately does not
 * contain, and that sentence is documentation, not a fact in the wrong place.
 */
describe('single-source-of-truth invariant', () => {
  const FORBIDDEN: readonly RegExp[] = [
    /0x0806/,
    /0x0800/,
    /\bopcode\b/i,
    /\bhtype\b/i,
    /\bhlen\b/i,
    /\bplen\b/i,
    /\bETHER_TYPE\b/,
    /\bARP_OPCODE\b/,
    /ff:ff:ff:ff:ff:ff/i,
    /\bencodeArp\b/,
    /\bencodeEthernet\b/,
    // Phase 4's stack brings its own facts to keep out: the magic cookie, option
    // codes, the ports, the broadcast address and the encoders themselves.
    /0x63825363/,
    /\bmagic\b/i,
    /\bDHCP_OPTION\b/,
    /\bDHCP_MESSAGE_TYPE\b/,
    /\bDHCP_OP\b/,
    /\bencodeDhcp\b/,
    /\bencodeIpv4\b/,
    /\bencodeUdp\b/,
    /\b255\.255\.255\.255\b/,
    /\bbroadcast flag\b/i,
    // The ports by name rather than by number: a bare 67 could legitimately be a
    // timestamp, and a false positive here would be a test that cries wolf.
    /\bDHCP_(CLIENT|SERVER)_PORT\b/,
    /\bport\b/i,
  ]

  /** Every scenario file there is, found rather than listed, so a new lesson is covered on the day it lands. */
  const scenarioFiles = readdirSync('src/lessons', { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => `src/lessons/${entry.name}/scenario.ts`)

  it('finds every lesson scenario', () => {
    expect(scenarioFiles.length).toBe(LESSONS.length)
  })

  it('keeps every protocol fact out of src/lessons', () => {
    for (const path of [...scenarioFiles, 'src/lessons/index.ts']) {
      const code = stripComments(readFileSync(path, 'utf8'))
      for (const pattern of FORBIDDEN) {
        expect(pattern.test(code), `${path} contains protocol detail matching ${pattern}`).toBe(
          false,
        )
      }
    }
  })

  it('leaves the DHCP lesson with nothing but hosts, a lease and timings', () => {
    const code = stripComments(readFileSync('src/lessons/dhcp/scenario.ts', 'utf8'))
    // A lease is scene intent: which address is on offer, for how long, and with
    // what mask, router and name server. How any of it is encoded is not.
    expect(code).toContain('10.0.0.50')
    expect(code).toContain('86400')
    expect(code).toContain('255.255.255.0')
    expect(code).toContain('linkDelayMs')
  })

  it('leaves only host addresses and timings behind', () => {
    const code = stripComments(readFileSync('src/lessons/arp/scenario.ts', 'utf8'))
    // The addresses and the link delay are legitimate scene intent.
    expect(code).toContain('10.0.0.1')
    expect(code).toContain('aa:bb:cc:00:00:01')
    expect(code).toContain('linkDelayMs')
  })

  it('forbids src/views from importing lesson content', () => {
    // Belt and braces: `.oxlintrc.json` enforces this too, but a lint config can
    // be edited away in a hurry and a failing test is harder to ignore.
    const files = readdirSync('src/views')
    expect(files.length).toBeGreaterThanOrEqual(8)
    for (const file of files) {
      const code = readFileSync(`src/views/${file}`, 'utf8')
      expect(code, `src/views/${file} imports lesson content`).not.toMatch(/from '.*lessons/)
    }
  })
})

function stripComments(code: string): string {
  return code.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '')
}

/** Every leaf a lesson can show must be explainable (criterion #6). */
describe('field explanations', () => {
  it('gives every decoded leaf field a description and a reference', () => {
    for (const lesson of LESSONS) {
      for (const packet of compileScenario(lesson.scenario).packets) {
        for (const node of leafFields(packet.tree)) {
          expect(node.description, `${node.id} has no description`).toBeTruthy()
          expect(node.reference, `${node.id} has no reference`).toBeTruthy()
        }
      }
    }
  })
})
