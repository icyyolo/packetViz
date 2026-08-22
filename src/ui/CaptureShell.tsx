/**
 * An imported capture in the same four layers a lesson uses.
 *
 * The views underneath are the ones the lessons render — they take a
 * `DecodedPacket` and know nothing about where it came from, which is the whole
 * reason a stranger's file can be dropped into them at all.
 *
 * Two things differ from a lesson, both forced by the data:
 *
 *   - there is no narration, because nobody wrote one for this file;
 *   - big captures are decoded lazily. Under `LADDER_MAX_PACKETS` every frame is
 *     decoded up front so the ladder can label its arrows; above it, the list is
 *     built from record headers alone and exactly one packet — the selected one —
 *     is ever decoded.
 */

import { useMemo } from 'react'
import { decodeFrame } from '../core/registry.ts'
import { frameAt, relativeMs, type PcapCapture } from '../core/pcap/read.ts'
import { compileCapture, isLadderSized, LADDER_MAX_PACKETS } from '../scenario/fromCapture.ts'
import { useVirtualClock } from '../timeline/useTimeline.ts'
import { useClockSnapshot } from '../timeline/useTimeline.ts'
import { FieldDetailPanel } from '../views/FieldDetailPanel.tsx'
import { FieldTreeView } from '../views/FieldTreeView.tsx'
import { FlowView } from '../views/FlowView.tsx'
import { HexView } from '../views/HexView.tsx'
import { LayoutView } from '../views/LayoutView.tsx'
import { TopologyView } from '../views/TopologyView.tsx'
import { useArpCaches } from '../views/arpCache.ts'
import { useSelection } from '../views/selection.ts'
import { Scrubber } from './Scrubber.tsx'

export type CaptureShellProps = {
  name: string
  capture: PcapCapture
  onClose: () => void
}

export function CaptureShell({ name, capture, onClose }: CaptureShellProps) {
  const { packetIndex, selectPacket, selectField } = useSelection()

  const ladder = isLadderSized(capture)
  const timeline = useMemo(() => (ladder ? compileCapture(capture) : null), [capture, ladder])
  const clock = useVirtualClock(timeline?.durationMs ?? 0)
  const { tMs } = useClockSnapshot(clock)
  const snapshots = useArpCaches(timeline ?? EMPTY_TIMELINE)

  const record = capture.records[packetIndex]
  // One decode, whichever mode we are in: eager captures reuse the timeline's,
  // lazy ones decode the selected frame and nothing else.
  const packet = useMemo(() => {
    if (timeline !== null) return timeline.packets[packetIndex]
    return record === undefined ? undefined : decodeFrame(frameAt(capture, record))
  }, [capture, packetIndex, record, timeline])

  const skipped = capture.totalRecords - capture.records.length

  return (
    <article className="lesson capture">
      <header className="lesson-head">
        <div>
          <h1>{name}</h1>
          <p className="lesson-blurb">
            {capture.totalRecords} packet{capture.totalRecords === 1 ? '' : 's'},{' '}
            {capture.byteOrder}, {capture.timeResolution} timestamps, captured{' '}
            {captureStart(capture)}. Everything below is decoded from these bytes by the same code
            the lessons use.
          </p>
        </div>
        <button type="button" className="export-button" onClick={onClose}>
          Load a different capture
        </button>
      </header>

      {skipped > 0 ? (
        <p className="import-message" role="status">
          Showing the first {capture.records.length} packets of {capture.totalRecords}. The
          remaining {skipped} were skipped: the reader walks every record header, but only this
          many are kept in memory.
        </p>
      ) : null}

      {capture.warnings.map((warning) => (
        <p className="import-message" role="status" key={warning}>
          {warning}
        </p>
      ))}

      {timeline === null ? (
        <p className="capture-note">
          Layers 1 and 2 are drawn for captures of up to {LADDER_MAX_PACKETS} packets — beyond
          that a ladder diagram stops being readable, and decoding every frame to label it stops
          being free. The packet list below is built from record headers alone; the packet you
          select is the only one decoded.
        </p>
      ) : (
        <>
          <section className="stage" aria-label="Topology and flow">
            <TopologyView timeline={timeline} tMs={tMs} />
            <FlowView timeline={timeline} snapshots={snapshots} tMs={tMs} />
          </section>
          <Scrubber clock={clock} timeline={timeline} />
          <p className="capture-note">
            The hosts are the Ethernet addresses these frames carry, and each one's label is an IP
            address read out of a packet it sent. A capture records one timestamp per packet, at
            one observation point, so the arrows are flat: there is no propagation delay in the
            file to draw.
          </p>
        </>
      )}

      <nav className="packet-list" aria-label="Packets">
        {capture.records.map((item, index) => (
          <button
            key={item.index}
            type="button"
            className={`packet-tab${index === packetIndex ? ' is-active' : ''}`}
            aria-current={index === packetIndex}
            onClick={() => {
              selectPacket(index)
              selectField(null)
              clock.pause()
              clock.seek(relativeMs(capture, item))
            }}
          >
            <span className="packet-tab-index">#{index + 1}</span>
            <span className="packet-tab-summary">
              {timeline?.packets[index]?.summary ?? `+${(relativeMs(capture, item) / 1000).toFixed(6)} s`}
            </span>
            <span className="packet-tab-size">{item.inclLen} B</span>
          </button>
        ))}
      </nav>

      {packet === undefined ? (
        <p className="empty">This capture holds no packets.</p>
      ) : (
        <>
          {packet.problems.length > 0 ? (
            <ul className="problems" aria-label="Decoder problems">
              {packet.problems.map((problem, index) => (
                <li key={index} className={`problem is-${problem.severity}`}>
                  <span className="problem-span">
                    byte {problem.byteStart}
                    {problem.byteLength > 1 ? `–${problem.byteStart + problem.byteLength - 1}` : ''}
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

          <details className="layout-details">
            <summary>Packet layout — the wire format, field by field</summary>
            <LayoutView packet={packet} />
          </details>
        </>
      )}
    </article>
  )
}

/** A stand-in so the ARP-cache hook can be called unconditionally. */
const EMPTY_TIMELINE = {
  hosts: [],
  linkDelayMs: 0,
  packets: [],
  marks: [],
  durationMs: 0,
}

function captureStart(capture: PcapCapture): string {
  const first = capture.records[0]
  if (first === undefined) return 'at an unknown time'
  return new Date(first.tsSec * 1000).toISOString().replace('.000Z', 'Z')
}
