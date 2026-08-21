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
          ⏮
        </button>
        <button
          type="button"
          className="scrubber-play"
          onClick={() => clock.toggle()}
          aria-label={playing ? 'Pause' : 'Play'}
        >
          {playing ? '⏸' : '⏵'}
        </button>
        <button type="button" onClick={() => stepTo(1)} aria-label="Next packet">
          ⏭
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
