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
]

export function findLesson(slug: string | undefined): Lesson | undefined {
  return LESSONS.find((lesson) => lesson.slug === slug)
}
