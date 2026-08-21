/**
 * Scene intent — and nothing else.
 *
 * A scenario says who is on the segment, how long the wire takes, and who
 * transmits when. It does NOT say what is in a packet: `build()` returns a byte
 * buffer produced by the encoders in `core`, and every protocol fact the UI
 * shows is read back out of that buffer by `decode()`.
 *
 * If a TTL, a port, a flag or an opcode ever appears in this file's types, the
 * single-source-of-truth invariant has been broken.
 */

export type Host = {
  /** Stable key used by events and by the topology/flow views. */
  id: string
  label: string
  mac: string
  ip: string
}

export type PacketEvent = {
  /** Milliseconds after the start of the scenario, at the moment of transmission. */
  tMs: number
  /** Host id of the sender. */
  from: string
  /** Host id of the intended receiver. `null` for a broadcast. */
  to: string | null
  /** Produces the frame. The only way protocol facts enter the system. */
  build: () => Uint8Array
}

export type Scenario = {
  hosts: Host[]
  /** Propagation delay across the segment. A scene constant, not a simulation. */
  linkDelayMs: number
  events: PacketEvent[]
}

/**
 * Lesson prose. Bound to timeline marks by index, never to field values, so a
 * packet the user has edited by hand degrades to stale narration rather than a
 * lie about its contents.
 */
export type NarrationStep = {
  title: string
  body: string
}

export type Narration = {
  intro: string
  /** `steps[i]` describes packet `i`. */
  steps: NarrationStep[]
}
