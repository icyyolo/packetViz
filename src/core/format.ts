/**
 * Address and number rendering, plus the parsers the encoders use.
 *
 * Parsers throw: their inputs come from scenario files we write, so a malformed
 * address is a authoring bug and should fail the build's tests, not decode to
 * something plausible.
 */

export function formatMac(raw: Uint8Array): string {
  return Array.from(raw, (b) => b.toString(16).padStart(2, '0')).join(':')
}

export function parseMac(text: string): Uint8Array {
  const parts = text.split(':')
  if (parts.length !== 6) {
    throw new Error(`parseMac(${JSON.stringify(text)}): expected 6 colon-separated octets`)
  }
  return Uint8Array.from(parts, (part) => {
    if (!/^[0-9a-fA-F]{2}$/.test(part)) {
      throw new Error(`parseMac(${JSON.stringify(text)}): bad octet ${JSON.stringify(part)}`)
    }
    return Number.parseInt(part, 16)
  })
}

export function formatIpv4(raw: Uint8Array): string {
  return Array.from(raw, (b) => b.toString(10)).join('.')
}

export function parseIpv4(text: string): Uint8Array {
  const parts = text.split('.')
  if (parts.length !== 4) {
    throw new Error(`parseIpv4(${JSON.stringify(text)}): expected 4 dot-separated octets`)
  }
  return Uint8Array.from(parts, (part) => {
    if (!/^\d{1,3}$/.test(part)) {
      throw new Error(`parseIpv4(${JSON.stringify(text)}): bad octet ${JSON.stringify(part)}`)
    }
    const value = Number.parseInt(part, 10)
    if (value > 255) {
      throw new Error(`parseIpv4(${JSON.stringify(text)}): octet ${part} exceeds 255`)
    }
    return value
  })
}

export function formatHexBytes(raw: Uint8Array): string {
  return Array.from(raw, (b) => b.toString(16).padStart(2, '0')).join(' ')
}

/** e.g. hex(0x0806, 4) === "0x0806" */
export function hex(value: number, digits: number): string {
  return `0x${value.toString(16).padStart(digits, '0')}`
}
