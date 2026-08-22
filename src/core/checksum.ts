/**
 * RFC 1071 one's-complement checksums.
 *
 * Two protocols in this project carry one: IPv4 over its own header, and UDP
 * over a pseudo-header built from the enclosing IP addresses plus the datagram.
 * Both use the same arithmetic, which is the reason RFC 1071 exists as its own
 * document rather than as a paragraph in each protocol's spec.
 *
 * The functions here are total and allocation-free over the frame: they read a
 * `Uint8Array` and return a number, and the only buffer any of them builds is
 * the fixed 12-byte UDP pseudo-header.
 *
 * A note on the `zeroFrom`/`zeroTo` window: a checksum is computed over a buffer
 * in which the checksum field itself reads as zero. Rather than copy the frame
 * to blank two bytes — which would mean allocating from a length a hostile
 * packet controls — the sum treats that window as zero while reading the
 * original bytes.
 */

/** Fold the carries out of an accumulated sum, leaving 16 bits. */
function fold(sum: number): number {
  let folded = sum
  while (folded > 0xffff) folded = (folded & 0xffff) + (folded >>> 16)
  return folded
}

/**
 * The RFC 1071 sum over `bytes`, folded to 16 bits. An odd final byte is
 * treated as the high half of a word padded with zero, as the RFC specifies.
 */
export function onesSum(bytes: Uint8Array, initial = 0, zeroFrom = -1, zeroTo = -1): number {
  const blank = (index: number): boolean => index >= zeroFrom && index < zeroTo
  let sum = initial

  for (let i = 0; i + 1 < bytes.length; i += 2) {
    const high = blank(i) ? 0 : (bytes[i] ?? 0)
    const low = blank(i + 1) ? 0 : (bytes[i + 1] ?? 0)
    sum += (high << 8) | low
  }
  if (bytes.length % 2 === 1) {
    const last = bytes.length - 1
    sum += (blank(last) ? 0 : (bytes[last] ?? 0)) << 8
  }
  return fold(sum)
}

/** The value that goes in the checksum field: the one's complement of the sum. */
export function complement(sum: number): number {
  return ~fold(sum) & 0xffff
}

/** Offset of the checksum field within an IPv4 header. */
const IPV4_CHECKSUM_OFFSET = 10

/**
 * Checksum of an IPv4 header. Computed with the checksum field read as zero, so
 * the same call both produces the value for the encoder and recomputes the
 * expected value for a decoder checking one it was given.
 */
export function ipv4Checksum(header: Uint8Array): number {
  return complement(onesSum(header, 0, IPV4_CHECKSUM_OFFSET, IPV4_CHECKSUM_OFFSET + 2))
}

/** Offset of the checksum field within a UDP header. */
const UDP_CHECKSUM_OFFSET = 6

/** Protocol number of UDP, as it appears in the pseudo-header. */
const IP_PROTOCOL_UDP = 17

/**
 * UDP checksum over the RFC 768 pseudo-header (source address, destination
 * address, a zero byte, the protocol number, and the UDP length) followed by the
 * datagram itself.
 *
 * The pseudo-header is the part worth understanding: it is not transmitted, it
 * exists so that a datagram delivered to the wrong host or the wrong protocol
 * fails its checksum. UDP's checksum therefore covers addresses that are not in
 * the UDP header at all, which is exactly why a decoder cannot verify it without
 * being told what enclosed it.
 */
export function udpChecksum(srcIp: Uint8Array, dstIp: Uint8Array, datagram: Uint8Array): number {
  const pseudo = new Uint8Array(12)
  pseudo.set(srcIp.subarray(0, 4), 0)
  pseudo.set(dstIp.subarray(0, 4), 4)
  pseudo[9] = IP_PROTOCOL_UDP
  pseudo[10] = (datagram.length >> 8) & 0xff
  pseudo[11] = datagram.length & 0xff

  const sum = onesSum(datagram, onesSum(pseudo), UDP_CHECKSUM_OFFSET, UDP_CHECKSUM_OFFSET + 2)

  // RFC 768: a computed checksum of zero is transmitted as all ones, because
  // zero is reserved to mean "no checksum was computed".
  return complement(sum) || 0xffff
}
