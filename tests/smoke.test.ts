import { describe, expect, it } from 'vitest'

describe('toolchain', () => {
  it('runs vitest', () => {
    expect(new Uint8Array([0xde, 0xad]).byteLength).toBe(2)
  })
})
