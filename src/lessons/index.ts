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
]

export function findLesson(slug: string | undefined): Lesson | undefined {
  return LESSONS.find((lesson) => lesson.slug === slug)
}
