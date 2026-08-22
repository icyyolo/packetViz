/**
 * The lesson registry.
 *
 * Holds slugs, titles and prose. It holds no protocol facts: a lesson card's
 * packet count and protocol badges are computed by compiling the scenario and
 * reading the decode (see `src/pages/HomePage.tsx`), never typed by hand here.
 */

import type { Narration, Scenario } from '../scenario/types.ts'
import { arpNarration } from './arp/narration.ts'
import { arpScenario } from './arp/scenario.ts'
import { arpSpoofingNarration } from './arp-spoofing/narration.ts'
import { arpSpoofingScenario } from './arp-spoofing/scenario.ts'
import { dhcpNarration } from './dhcp/narration.ts'
import { dhcpScenario } from './dhcp/scenario.ts'
import { dnsNarration } from './dns/narration.ts'
import { dnsScenario } from './dns/scenario.ts'
import { pingNarration } from './ping/narration.ts'
import { pingScenario } from './ping/scenario.ts'
import { tcpHandshakeNarration } from './tcp-handshake/narration.ts'
import { tcpHandshakeScenario } from './tcp-handshake/scenario.ts'

export type LessonMeta = {
  slug: string
  title: string
  blurb: string
}

export type Lesson = LessonMeta & {
  scenario: Scenario
  narration: Narration
  /** Name of the exported capture file. */
  filename: string
}

export const LESSONS: readonly Lesson[] = [
  {
    slug: 'arp',
    title: 'ARP: finding a MAC address',
    blurb:
      'An IP address is not enough to send a frame. Watch a host discover its neighbour\'s hardware address, and read the answer out of the bytes.',
    scenario: arpScenario,
    narration: arpNarration,
    filename: 'arp.pcap',
  },
  {
    slug: 'arp-spoofing',
    title: 'ARP spoofing: the cache is the vulnerability',
    blurb:
      'A reply nobody asked for, and a neighbour cache that believes it anyway. The same four packets a switch sees every day, one of which quietly redirects a host\'s traffic.',
    scenario: arpSpoofingScenario,
    narration: arpSpoofingNarration,
    filename: 'arp-spoofing.pcap',
  },
  {
    slug: 'dhcp',
    title: 'DHCP: how a host gets an address',
    blurb:
      'Four broadcasts between a host with no address and a server willing to lend it one — and the whole Ethernet, IPv4, UDP and DHCP stack in every packet.',
    scenario: dhcpScenario,
    narration: dhcpNarration,
    filename: 'dhcp.pcap',
  },
  {
    slug: 'ping',
    title: 'Ping: the smallest useful program',
    blurb:
      'Send something, ask for it back, time how long it takes. Four ICMP messages with no ports, no connection and no length field of their own.',
    scenario: pingScenario,
    narration: pingNarration,
    filename: 'ping.pcap',
  },
  {
    slug: 'tcp-handshake',
    title: 'TCP: three packets before a byte of data',
    blurb:
      'Two random numbers, exchanged and acknowledged. The first lesson here where the fact that matters lives between the packets rather than inside one.',
    scenario: tcpHandshakeScenario,
    narration: tcpHandshakeNarration,
    filename: 'tcp-handshake.pcap',
  },
  {
    slug: 'dns',
    title: 'DNS: a name that is not in the field',
    blurb:
      'A query and its answer, where the answer\'s name is two bytes meaning "the name I already sent you". Pointer compression, and what a decoder has to do about loops.',
    scenario: dnsScenario,
    narration: dnsNarration,
    filename: 'dns.pcap',
  },
]

export function findLesson(slug: string | undefined): Lesson | undefined {
  return LESSONS.find((lesson) => lesson.slug === slug)
}
