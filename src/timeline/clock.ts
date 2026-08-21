/**
 * Deterministic virtual clock.
 *
 * There is one number, `t`, and every view is a pure function of it. That is
 * what makes the timeline scrubbable and seekable, and what lets Phase 6 capture
 * byte-identical screenshots by seeking to a fixed `t` instead of waiting on
 * animation frames. A tweening library that owns its own time cannot be seeked,
 * which is why there isn't one.
 *
 * The rAF loop is injectable so the clock is testable in node without a browser.
 */

export type ClockScheduler = {
  request: (callback: (nowMs: number) => void) => number
  cancel: (handle: number) => void
  now: () => number
}

export type ClockSnapshot = {
  tMs: number
  playing: boolean
  rate: number
  durationMs: number
}

const browserScheduler: ClockScheduler = {
  request: (callback) => requestAnimationFrame(callback),
  cancel: (handle) => cancelAnimationFrame(handle),
  now: () => performance.now(),
}

export class VirtualClock {
  private tMs = 0
  private isPlaying = false
  private rate = 1
  private duration: number
  private readonly scheduler: ClockScheduler
  private readonly listeners = new Set<() => void>()
  private handle: number | null = null
  private lastFrameMs = 0
  private snapshot: ClockSnapshot

  constructor(durationMs: number, scheduler: ClockScheduler = browserScheduler) {
    this.duration = Math.max(0, durationMs)
    this.scheduler = scheduler
    this.snapshot = this.buildSnapshot()
  }

  getSnapshot(): ClockSnapshot {
    return this.snapshot
  }

  get t(): number {
    return this.tMs
  }

  get playing(): boolean {
    return this.isPlaying
  }

  get durationMs(): number {
    return this.duration
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener)
    return () => {
      this.listeners.delete(listener)
    }
  }

  seek(ms: number): void {
    const next = clamp(ms, 0, this.duration)
    if (next === this.tMs) return
    this.tMs = next
    this.emit()
  }

  /** Nudge by a fixed amount and stop, for the step buttons. */
  step(deltaMs: number): void {
    this.pause()
    this.seek(this.tMs + deltaMs)
  }

  play(): void {
    if (this.isPlaying || this.duration === 0) return
    // Replaying from the end restarts rather than sitting still.
    if (this.tMs >= this.duration) this.tMs = 0
    this.isPlaying = true
    this.lastFrameMs = this.scheduler.now()
    this.scheduleFrame()
    this.emit()
  }

  pause(): void {
    if (!this.isPlaying) return
    this.isPlaying = false
    if (this.handle !== null) {
      this.scheduler.cancel(this.handle)
      this.handle = null
    }
    this.emit()
  }

  toggle(): void {
    if (this.isPlaying) this.pause()
    else this.play()
  }

  setRate(rate: number): void {
    const next = clamp(rate, 0.05, 8)
    if (next === this.rate) return
    this.rate = next
    this.emit()
  }

  setDuration(durationMs: number): void {
    const next = Math.max(0, durationMs)
    if (next === this.duration) return
    this.duration = next
    this.tMs = clamp(this.tMs, 0, next)
    this.emit()
  }

  /** Advance by wall-clock milliseconds, scaled by rate. Exposed for tests. */
  advance(deltaMs: number): void {
    if (deltaMs <= 0) return
    const next = clamp(this.tMs + deltaMs * this.rate, 0, this.duration)
    const reachedEnd = next >= this.duration
    this.tMs = next
    if (reachedEnd && this.isPlaying) {
      this.isPlaying = false
      if (this.handle !== null) {
        this.scheduler.cancel(this.handle)
        this.handle = null
      }
    }
    this.emit()
  }

  dispose(): void {
    this.listeners.clear()
    if (this.handle !== null) {
      this.scheduler.cancel(this.handle)
      this.handle = null
    }
    this.isPlaying = false
  }

  private scheduleFrame(): void {
    this.handle = this.scheduler.request((nowMs) => {
      this.handle = null
      if (!this.isPlaying) return
      const delta = nowMs - this.lastFrameMs
      this.lastFrameMs = nowMs
      this.advance(delta)
      if (this.isPlaying) this.scheduleFrame()
    })
  }

  private buildSnapshot(): ClockSnapshot {
    return {
      tMs: this.tMs,
      playing: this.isPlaying,
      rate: this.rate,
      durationMs: this.duration,
    }
  }

  private emit(): void {
    this.snapshot = this.buildSnapshot()
    for (const listener of this.listeners) listener()
  }
}

function clamp(value: number, min: number, max: number): number {
  if (Number.isNaN(value)) return min
  return Math.min(max, Math.max(min, value))
}
