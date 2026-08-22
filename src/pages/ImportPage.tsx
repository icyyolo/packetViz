/**
 * `#/import` — the same viewer, pointed at a file this project did not write.
 *
 * Every lesson so far proves the decoder against bytes our own encoders
 * produced. This page is where that stops being circular: a capture from
 * Wireshark or tcpdump arrives with its own MAC addresses, its own timestamps
 * and, quite often, protocols we have no decoder for. It has to render or fail
 * legibly, and never go blank — which is what the reader's message path and the
 * error boundary below are for.
 */

import { useState } from 'react'
import { Link } from 'react-router-dom'
import type { PcapCapture } from '../core/pcap/read.ts'
import { CaptureShell } from '../ui/CaptureShell.tsx'
import { ErrorBoundary } from '../ui/ErrorBoundary.tsx'
import { ImportPcapDropzone } from '../ui/ImportPcapDropzone.tsx'
import { SelectionProvider } from '../views/SelectionContext.tsx'

type Loaded = { name: string; capture: PcapCapture }

export function ImportPage() {
  const [loaded, setLoaded] = useState<Loaded | null>(null)

  if (loaded === null) {
    return (
      <div className="import">
        <header className="home-head">
          <h1>Open your own capture</h1>
          <p className="home-tagline">
            Drop in a .pcap and read it in the same four layers as a lesson: the segment, the
            ladder, the decoded fields and the bytes they came from. Export a lesson's capture and
            drop it back in — it decodes to the same values.
          </p>
        </header>

        <ImportPcapDropzone onLoad={(name, capture) => setLoaded({ name, capture })} />

        <p className="import-foot">
          No capture handy? <Link to="/lesson/dhcp">Open the DHCP lesson</Link> and export its
          four packets first.
        </p>
      </div>
    )
  }

  return (
    <ErrorBoundary
      key={loaded.name}
      title="This capture could not be displayed."
      action={
        <button type="button" className="export-button" onClick={() => setLoaded(null)}>
          Load a different capture
        </button>
      }
    >
      <SelectionProvider key={loaded.name} packetCount={loaded.capture.records.length}>
        <CaptureShell
          name={loaded.name}
          capture={loaded.capture}
          onClose={() => setLoaded(null)}
        />
      </SelectionProvider>
    </ErrorBoundary>
  )
}
