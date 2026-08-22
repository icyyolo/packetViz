/**
 * The way somebody else's bytes get in.
 *
 * Reads the file with the File API and hands it straight to `readPcap`. There is
 * no upload, no server and no parsing library: the capture never leaves the tab.
 * Everything that can go wrong — wrong format, wrong link type, truncated file —
 * comes back as a message from the reader rather than as an exception, so this
 * component has nothing to catch.
 */

import { useRef, useState } from 'react'
import { readPcap, type PcapCapture } from '../core/pcap/read.ts'

export type ImportPcapDropzoneProps = {
  onLoad: (name: string, capture: PcapCapture) => void
}

export function ImportPcapDropzone({ onLoad }: ImportPcapDropzoneProps) {
  const [message, setMessage] = useState<string | null>(null)
  const [dragging, setDragging] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)

  const accept = async (file: File | undefined): Promise<void> => {
    if (file === undefined) return
    setMessage(null)

    const bytes = new Uint8Array(await file.arrayBuffer())
    const result = readPcap(bytes)
    if (!result.ok) {
      setMessage(result.message)
      return
    }
    onLoad(file.name, result.capture)
  }

  return (
    <div className="dropzone-wrap">
      <div
        className={`dropzone${dragging ? ' is-dragging' : ''}`}
        onDragOver={(event) => {
          event.preventDefault()
          setDragging(true)
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(event) => {
          event.preventDefault()
          setDragging(false)
          void accept(event.dataTransfer.files[0])
        }}
      >
        <p className="dropzone-lead">Drop a .pcap here</p>
        <p className="dropzone-note">
          Classic libpcap, either byte order, Ethernet frames. Nothing is uploaded — the file is
          read in this tab.
        </p>
        <button type="button" className="export-button" onClick={() => inputRef.current?.click()}>
          Choose a file
        </button>
        <input
          ref={inputRef}
          className="visually-hidden"
          type="file"
          accept=".pcap,.cap,application/vnd.tcpdump.pcap"
          aria-label="Capture file"
          onChange={(event) => {
            void accept(event.target.files?.[0])
            // Lets the same file be chosen twice in a row after a failure.
            event.target.value = ''
          }}
        />
      </div>

      {message === null ? null : (
        <p className="import-message" role="alert">
          {message}
        </p>
      )}
    </div>
  )
}
