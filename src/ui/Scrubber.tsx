/**
 * Transport controls over the virtual clock. Everything writes to `t`; nothing
 * owns animation state of its own.
 */

import type { CompiledTimeline } from '../scenario/compile.ts'
import type { VirtualClock } from '../timeline/clock.ts'
import { useClockSnapshot } from '../timeline/useTimeline.ts'

export type ScrubberProps = {
  clock: VirtualClock
  timeline: CompiledTimeline
}

const RATES = [0.25, 0.5, 1, 2]

/**
 * Drawn rather than typed. The media-control characters (U+23EE and friends)
 * depend on a font that carries them, and a headless Chromium renders them as
 * empty boxes — which is how this was noticed. A path has no such dependency.
 */
const SHAPES: Record<'previous' | 'play' | 'pause' | 'next', string> = {
  previous: 'M3 2h2v8H3zM11 2v8L5 6z',
  play: 'M3 2l8 4-8 4z',
  pause: 'M3 2h2.5v8H3zM7.5 2H10v8H7.5z',
  next: 'M9 2h2v8H9zM1 2l6 4-6 4z',
}

function Icon({ shape }: { shape: keyof typeof SHAPES }) {
  return (
    <svg className="scrubber-icon" viewBox="0 0 14 12" width="14" height="12" aria-hidden="true">
      <path d={SHAPES[shape]} fill="currentColor" />
    </svg>
  )
}

export function Scrubber({ clock, timeline }: ScrubberProps) {
  const { tMs, playing, rate, durationMs } = useClockSnapshot(clock)
  const stops = timeline.marks.map((mark) => mark.sentMs)

  const stepTo = (direction: -1 | 1): void => {
    const candidates = direction === 1 ? stops.filter((s) => s > tMs + 0.5) : stops.filter((s) => s < tMs - 0.5)
    const target = direction === 1 ? Math.min(...candidates) : Math.max(...candidates)
    clock.pause()
    clock.seek(Number.isFinite(target) ? target : direction === 1 ? durationMs : 0)
  }

  return (
    <div className="scrubber">
      <div className="scrubber-buttons">
        <button type="button" onClick={() => stepTo(-1)} aria-label="Previous packet">
          <Icon shape="previous" />
        </button>
        <button
          type="button"
          className="scrubber-play"
          onClick={() => clock.toggle()}
          aria-label={playing ? 'Pause' : 'Play'}
        >
          <Icon shape={playing ? 'pause' : 'play'} />
        </button>
        <button type="button" onClick={() => stepTo(1)} aria-label="Next packet">
          <Icon shape="next" />
        </button>
      </div>

      <input
        className="scrubber-range"
        type="range"
        min={0}
        max={Math.max(1, durationMs)}
        step={1}
        value={tMs}
        aria-label="Timeline position in milliseconds"
        aria-valuetext={`${tMs.toFixed(0)} of ${durationMs.toFixed(0)} milliseconds`}
        onChange={(event) => {
          clock.pause()
          clock.seek(Number(event.target.value))
        }}
      />

      <output className="scrubber-time">
        {tMs.toFixed(0)} / {durationMs.toFixed(0)} ms
      </output>

      <label className="scrubber-rate">
        <span className="visually-hidden">Playback rate</span>
        <select value={rate} onChange={(event) => clock.setRate(Number(event.target.value))}>
          {RATES.map((value) => (
            <option key={value} value={value}>
              {value}×
            </option>
          ))}
        </select>
      </label>
    </div>
  )
}
