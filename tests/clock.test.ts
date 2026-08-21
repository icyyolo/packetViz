import { describe, expect, it, vi } from 'vitest'
import { VirtualClock, type ClockScheduler } from '../src/timeline/clock.ts'

/** A scheduler that never fires on its own, so tests drive time by hand. */
function manualScheduler(): ClockScheduler & { fire: (nowMs: number) => void } {
  let pending: ((nowMs: number) => void) | null = null
  return {
    request: (callback) => {
      pending = callback
      return 1
    },
    cancel: () => {
      pending = null
    },
    now: () => 0,
    fire: (nowMs) => {
      const callback = pending
      pending = null
      callback?.(nowMs)
    },
  }
}

describe('VirtualClock', () => {
  it('seeks without needing an animation frame', () => {
    const clock = new VirtualClock(3000, manualScheduler())
    clock.seek(1200)
    expect(clock.t).toBe(1200)
    expect(clock.getSnapshot().tMs).toBe(1200)
  })

  it('clamps seeks to [0, duration]', () => {
    const clock = new VirtualClock(1000, manualScheduler())
    clock.seek(-50)
    expect(clock.t).toBe(0)
    clock.seek(99_999)
    expect(clock.t).toBe(1000)
    clock.seek(Number.NaN)
    expect(clock.t).toBe(0)
  })

  it('notifies subscribers and hands out a fresh snapshot', () => {
    const clock = new VirtualClock(1000, manualScheduler())
    const listener = vi.fn()
    const unsubscribe = clock.subscribe(listener)

    const before = clock.getSnapshot()
    clock.seek(500)
    expect(listener).toHaveBeenCalledTimes(1)
    expect(clock.getSnapshot()).not.toBe(before)

    unsubscribe()
    clock.seek(600)
    expect(listener).toHaveBeenCalledTimes(1)
  })

  it('does not emit when the value is unchanged', () => {
    const clock = new VirtualClock(1000, manualScheduler())
    clock.seek(500)
    const listener = vi.fn()
    clock.subscribe(listener)
    clock.seek(500)
    expect(listener).not.toHaveBeenCalled()
  })

  it('advances by wall-clock delta scaled by rate', () => {
    const clock = new VirtualClock(10_000, manualScheduler())
    clock.advance(100)
    expect(clock.t).toBe(100)
    clock.setRate(2)
    clock.advance(100)
    expect(clock.t).toBe(300)
    clock.setRate(0.5)
    clock.advance(100)
    expect(clock.t).toBe(350)
  })

  it('drives itself from the scheduler while playing, and stops at the end', () => {
    const scheduler = manualScheduler()
    const clock = new VirtualClock(500, scheduler)

    clock.play()
    expect(clock.playing).toBe(true)

    scheduler.fire(200)
    expect(clock.t).toBe(200)

    scheduler.fire(700)
    expect(clock.t).toBe(500)
    expect(clock.playing).toBe(false)
  })

  it('restarts from zero when play is pressed at the end', () => {
    const clock = new VirtualClock(500, manualScheduler())
    clock.seek(500)
    clock.play()
    expect(clock.t).toBe(0)
    expect(clock.playing).toBe(true)
  })

  it('step pauses and nudges', () => {
    const clock = new VirtualClock(1000, manualScheduler())
    clock.play()
    clock.step(250)
    expect(clock.playing).toBe(false)
    expect(clock.t).toBe(250)
  })

  it('keeps t inside a duration that shrinks', () => {
    const clock = new VirtualClock(1000, manualScheduler())
    clock.seek(900)
    clock.setDuration(400)
    expect(clock.t).toBe(400)
  })
})
