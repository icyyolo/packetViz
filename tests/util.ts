export function fromHex(text: string): Uint8Array {
  const clean = text.replace(/\s+/g, '')
  if (clean.length % 2 !== 0) throw new Error('fromHex: odd number of hex digits')
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}
