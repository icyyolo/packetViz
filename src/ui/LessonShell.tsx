/**
 * Composes the four layers around one compiled timeline.
 *
 * This is the boundary where lesson prose reaches the UI. The layer views
 * underneath receive a `DecodedPacket` and nothing else — `.oxlintrc.json`
 * forbids anything in `src/views/**` from importing `src/lessons/**`, so the
 * single-source-of-truth invariant is a build failure rather than a convention.
 */

import { markAt, type CompiledTimeline } from '../scenario/compile.ts'
import type { Narration } from '../scenario/types.ts'
import type { VirtualClock } from '../timeline/clock.ts'
import { useClockSnapshot } from '../timeline/useTimeline.ts'
import { FieldDetailPanel } from '../views/FieldDetailPanel.tsx'
import { FieldTreeView } from '../views/FieldTreeView.tsx'
import { FlowView } from '../views/FlowView.tsx'
import { HexView } from '../views/HexView.tsx'
import { TopologyView } from '../views/TopologyView.tsx'
import { useSelection } from '../views/selection.ts'
import { ExportPcapButton } from './ExportPcapButton.tsx'
import { Scrubber } from './Scrubber.tsx'

export type LessonShellProps = {
  title: string
  blurb: string
  timeline: CompiledTimeline
  narration: Narration
  filename: string
  clock: VirtualClock
}

export function LessonShell(props: LessonShellProps) {
  const { title, blurb, timeline, narration, filename, clock } = props
  const { tMs } = useClockSnapshot(clock)
  const { packetIndex, selectPacket, selectField } = useSelection()

  const currentMark = markAt(timeline.marks, tMs)
  const step = currentMark >= 0 ? narration.steps[currentMark] : undefined
  const packet = timeline.packets[packetIndex]

  return (
    <article className="lesson">
      <header className="lesson-head">
        <div>
          <h1>{title}</h1>
          <p className="lesson-blurb">{blurb}</p>
        </div>
        <ExportPcapButton timeline={timeline} filename={filename} />
      </header>

      <section className="stage" aria-label="Topology and flow">
        <TopologyView timeline={timeline} tMs={tMs} />
        <FlowView timeline={timeline} tMs={tMs} />
      </section>

      <Scrubber clock={clock} timeline={timeline} />

      <section className="narration" aria-live="polite">
        <h2>{step?.title ?? 'Before the exchange'}</h2>
        <p>{step?.body ?? narration.intro}</p>
      </section>

      <nav className="packet-tabs" aria-label="Packets">
        {timeline.packets.map((decoded, index) => (
          <button
            key={index}
            type="button"
            className={`packet-tab${index === packetIndex ? ' is-active' : ''}`}
            aria-current={index === packetIndex}
            onClick={() => {
              selectPacket(index)
              selectField(null)
              clock.pause()
              clock.seek(timeline.marks[index]?.arrivedMs ?? 0)
            }}
          >
            <span className="packet-tab-index">#{index + 1}</span>
            <span className="packet-tab-summary">{decoded.summary}</span>
            <span className="packet-tab-size">{decoded.frame.length} B</span>
          </button>
        ))}
      </nav>

      {packet === undefined ? (
        <p className="empty">This scenario produced no packets.</p>
      ) : (
        <>
          {packet.problems.length > 0 ? (
            <ul className="problems" aria-label="Decoder problems">
              {packet.problems.map((problem, index) => (
                <li key={index} className={`problem is-${problem.severity}`}>
                  <span className="problem-span">
                    byte {problem.byteStart}
                    {problem.byteLength > 1
                      ? `–${problem.byteStart + problem.byteLength - 1}`
                      : ''}
                  </span>
                  {problem.message}
                </li>
              ))}
            </ul>
          ) : null}

          <section className="panes">
            <div className="pane pane-tree">
              <h2>Decoded fields</h2>
              <FieldTreeView packet={packet} />
            </div>
            <div className="pane pane-hex">
              <h2>Bytes on the wire</h2>
              <HexView packet={packet} />
            </div>
            <div className="pane pane-detail">
              <h2>Field detail</h2>
              <FieldDetailPanel packet={packet} />
            </div>
          </section>
        </>
      )}
    </article>
  )
}
