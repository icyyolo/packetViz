import { describe, expect, it } from 'vitest'
import { runSpec, specBytes, enumRender, type FieldSpec } from '../src/core/spec.ts'
import { fromHex } from './util.ts'

const num: FieldSpec['render'] = (_raw, ctx) => String(ctx.num)

const TOY: readonly FieldSpec[] = [
  { id: 'toy.a', name: 'A', bits: 8, render: num, description: 'a' },
  { id: 'toy.b', name: 'B', bits: 16, render: num, description: 'b' },
  { id: 'toy.c', name: 'C', bits: 24, render: num, description: 'c' },
]

describe('runSpec', () => {
  it('lays a 3-field spec over 6 bytes at the right offsets', () => {
    const run = runSpec(TOY, fromHex('01 0203 040506'), 0)

    expect(specBytes(TOY)).toBe(6)
    expect(run.byteLength).toBe(6)
    expect(run.problems).toEqual([])
    expect(run.nodes.map((n) => [n.id, n.byteStart, n.byteLength])).toEqual([
      ['toy.a', 0, 1],
      ['toy.b', 1, 2],
      ['toy.c', 3, 3],
    ])
    expect(run.nodes.map((n) => n.value)).toEqual(['1', '515', '263430'])
  })

  it('emits ABSOLUTE offsets when run at a non-zero offset', () => {
    const frame = fromHex('ffffffffffffff 01 0203 040506')
    const run = runSpec(TOY, frame, 7)
    expect(run.nodes.map((n) => n.byteStart)).toEqual([7, 8, 10])
    expect(run.byteLength).toBe(6)
  })

  it('tracks a bit cursor for sub-byte fields and highlights the containing byte', () => {
    const specs: readonly FieldSpec[] = [
      { id: 'x.version', name: 'Version', bits: 4, render: num, description: 'v' },
      { id: 'x.ihl', name: 'IHL', bits: 4, render: num, description: 'i' },
      { id: 'x.dscp', name: 'DSCP', bits: 8, render: num, description: 'd' },
    ]
    const run = runSpec(specs, fromHex('4500'), 0)

    expect(run.nodes.map((n) => [n.id, n.byteStart, n.byteLength, n.bitOffset, n.bitLength])).toEqual([
      ['x.version', 0, 1, 0, 4],
      ['x.ihl', 0, 1, 4, 4],
      ['x.dscp', 1, 1, undefined, undefined],
    ])
    expect(run.nodes.map((n) => n.value)).toEqual(['4', '5', '0'])
  })

  it('stops at truncation, names the field, and gives the problem a byte span', () => {
    const run = runSpec(TOY, fromHex('0102'), 0)

    expect(run.nodes.map((n) => n.id)).toEqual(['toy.a'])
    expect(run.problems).toHaveLength(1)
    expect(run.problems[0]?.severity).toBe('error')
    expect(run.problems[0]?.message).toContain('Truncated at B')
    expect(run.problems[0]).toMatchObject({ byteStart: 1, byteLength: 1 })
  })

  it('returns views into the frame, never copies', () => {
    const frame = fromHex('01 0203 040506')
    const run = runSpec(TOY, frame, 0)
    for (const node of run.nodes) {
      expect(node.raw.buffer).toBe(frame.buffer)
      expect(node.raw.byteOffset).toBe(node.byteStart)
    }
  })

  it('exposes prior field values to later renderers', () => {
    const specs: readonly FieldSpec[] = [
      { id: 'toy.len', name: 'Len', bits: 8, render: num, description: 'l' },
      {
        id: 'toy.echo',
        name: 'Echo',
        bits: 8,
        render: (_raw, ctx) => `len was ${ctx.values.get('toy.len')}`,
        description: 'e',
      },
    ]
    expect(runSpec(specs, fromHex('0700'), 0).nodes[1]?.value).toBe('len was 7')
  })
})

describe('enumRender', () => {
  it('names known values and refuses to hide unknown ones', () => {
    const render = enumRender({ 1: 'Request', 2: 'Reply' })
    const ctx = { frame: new Uint8Array(0), num: 1, values: new Map<string, number>() }
    expect(render(new Uint8Array(0), ctx)).toBe('1 (Request)')
    expect(render(new Uint8Array(0), { ...ctx, num: 7 })).toBe('7 (unknown)')
  })
})
