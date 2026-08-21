import { Link } from 'react-router-dom'

/**
 * Placeholder. The reader lands in Phase 7 (`src/core/pcap/read.ts`), with lazy
 * record-header walking and a hard packet cap. The route exists now so the
 * navigation is real rather than aspirational.
 */
export function ImportPage() {
  return (
    <div className="not-found">
      <h1>Import a capture</h1>
      <p>
        Not built yet — this lands in Phase 7, alongside the pcap reader. Until then the export
        direction works: open a lesson and download its capture.
      </p>
      <p>
        <Link to="/">Back to the lessons</Link>
      </p>
    </div>
  )
}
