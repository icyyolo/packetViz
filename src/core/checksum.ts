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

/** Offset of the checksum field within an ICMP message. */
const ICMP_CHECKSUM_OFFSET = 2

/**
 * Checksum of an ICMP message: the header and the data together, with no
 * pseudo-header. ICMP rides on IP and nothing else, so there is no wrong
 * protocol or wrong host for it to be delivered to and nothing outside the
 * message worth covering.
 */
export function icmpChecksum(message: Uint8Array): number {
  return complement(onesSum(message, 0, ICMP_CHECKSUM_OFFSET, ICMP_CHECKSUM_OFFSET + 2))
}

/** Offset of the checksum field within a UDP header. */
const UDP_CHECKSUM_OFFSET = 6

/** Offset of the checksum field within a TCP header. */
const TCP_CHECKSUM_OFFSET = 16

/** Protocol numbers as they appear in the pseudo-header. */
const IP_PROTOCOL_TCP = 6
const IP_PROTOCOL_UDP = 17

/**
 * Sum over the twelve-byte pseudo-header both transport checksums start from:
 * source address, destination address, a zero byte, the protocol number, and
 * the length of the segment or datagram.
 *
 * The pseudo-header is the part worth understanding: it is not transmitted, it
 * exists so that a segment delivered to the wrong host or the wrong protocol
 * fails its checksum. A transport checksum therefore covers addresses that are
 * not in the transport header at all, which is exactly why a decoder cannot
 * verify one without being told what enclosed it.
 *
 * It is also the only buffer these functions allocate, and its size is fixed —
 * never taken from a length field a hostile packet controls.
 */
function pseudoHeaderSum(
  srcIp: Uint8Array,
  dstIp: Uint8Array,
  protocol: number,
  length: number,
): number {
  const pseudo = new Uint8Array(12)
  pseudo.set(srcIp.subarray(0, 4), 0)
  pseudo.set(dstIp.subarray(0, 4), 4)
  pseudo[9] = protocol
  pseudo[10] = (length >> 8) & 0xff
  pseudo[11] = length & 0xff
  return onesSum(pseudo)
}

/** UDP checksum over the RFC 768 pseudo-header followed by the datagram itself. */
export function udpChecksum(srcIp: Uint8Array, dstIp: Uint8Array, datagram: Uint8Array): number {
  const initial = pseudoHeaderSum(srcIp, dstIp, IP_PROTOCOL_UDP, datagram.length)
  const sum = onesSum(datagram, initial, UDP_CHECKSUM_OFFSET, UDP_CHECKSUM_OFFSET + 2)

  // RFC 768: a computed checksum of zero is transmitted as all ones, because
  // zero is reserved to mean "no checksum was computed".
  return complement(sum) || 0xffff
}

/**
 * TCP checksum, RFC 9293 §3.1 — the same pseudo-header with a different protocol
 * number, over the header, the options and the data.
 *
 * The one difference from UDP is that there is no opt-out: TCP has no "did not
 * compute" value, so a computed sum of zero is transmitted as zero and means
 * exactly that. TCP also has no length field of its own, so the length in the
 * pseudo-header is one IPv4 gave it — a checksum that depends on a number
 * carried in a different header.
 */
export function tcpChecksum(srcIp: Uint8Array, dstIp: Uint8Array, segment: Uint8Array): number {
  const initial = pseudoHeaderSum(srcIp, dstIp, IP_PROTOCOL_TCP, segment.length)
  return complement(onesSum(segment, initial, TCP_CHECKSUM_OFFSET, TCP_CHECKSUM_OFFSET + 2))
}
