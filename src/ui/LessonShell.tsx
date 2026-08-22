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
import { ArpCacheView } from '../views/ArpCacheView.tsx'
import { FieldDetailPanel } from '../views/FieldDetailPanel.tsx'
import { FieldTreeView } from '../views/FieldTreeView.tsx'
import { FlowView } from '../views/FlowView.tsx'
import { HexView } from '../views/HexView.tsx'
import { LayoutView } from '../views/LayoutView.tsx'
import { PacketDiffView } from '../views/PacketDiffView.tsx'
import { TopologyView } from '../views/TopologyView.tsx'
import { useArpCaches } from '../views/arpCache.ts'
import { useEditableTimeline } from '../views/edits.ts'
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
  const { title, blurb, narration, filename, clock } = props
  const { tMs } = useClockSnapshot(clock)
  const { packetIndex, selectPacket, selectField } = useSelection()

  // Layer 4 is writable, so every layer below reads the EDITED timeline: the
  // ladder's labels, the neighbour caches and the exported capture are all
  // decodes of whatever bytes the frame currently holds, which is the whole
  // point of letting a visitor type into the hex grid.
  const { timeline, edited, setByte, reset } = useEditableTimeline(props.timeline)

  const snapshots = useArpCaches(timeline)
  const currentMark = markAt(timeline.marks, tMs)
  const step = currentMark >= 0 ? narration.steps[currentMark] : undefined
  const packet = timeline.packets[packetIndex]

  // Diff against the neighbouring packet: for the first one that means the
  // packet it provokes, which for ARP is the request/reply swap.
  const otherIndex = packetIndex === 0 ? 1 : packetIndex - 1
  const other = timeline.packets[otherIndex]

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
        <FlowView timeline={timeline} snapshots={snapshots} tMs={tMs} />
      </section>

      <Scrubber clock={clock} timeline={timeline} />

      <section className="narration" aria-live="polite">
        <h2>{step?.title ?? 'Before the exchange'}</h2>
        <p>{step?.body ?? narration.intro}</p>
      </section>

      <section className="cache-section" aria-label="Neighbour caches">
        <h2>Neighbour caches at {tMs.toFixed(0)} ms</h2>
        <ArpCacheView timeline={timeline} snapshots={snapshots} tMs={tMs} />
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
            {edited.has(index) ? <span className="packet-tab-edited">modified</span> : null}
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
              <h2>
                Bytes on the wire
                {edited.has(packetIndex) ? (
                  <span className="edited-badge">modified</span>
                ) : null}
              </h2>
              {edited.has(packetIndex) ? (
                <button
                  type="button"
                  className="reset-button"
                  onClick={() => reset(packetIndex)}
                >
                  Reset to the scenario's bytes
                </button>
              ) : null}
              <HexView
                packet={packet}
                baseline={props.timeline.packets[packetIndex]?.frame}
                onEditByte={(offset, value) => setByte(packetIndex, offset, value)}
              />
            </div>
            <div className="pane pane-detail">
              <h2>Field detail</h2>
              <FieldDetailPanel packet={packet} />
            </div>
          </section>

          {other === undefined ? null : (
            <details className="layout-details">
              <summary>
                Difference from packet #{otherIndex + 1}
              </summary>
              <div className="diff">
                <PacketDiffView
                  left={other}
                  leftIndex={otherIndex}
                  right={packet}
                  rightIndex={packetIndex}
                />
              </div>
            </details>
          )}

          <details className="layout-details">
            <summary>Packet layout — the wire format, field by field</summary>
            <LayoutView packet={packet} />
          </details>
        </>
      )}
    </article>
  )
}
