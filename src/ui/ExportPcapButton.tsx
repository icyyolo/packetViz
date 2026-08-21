/**
 * Export the compiled timeline as a real .pcap.
 *
 * This is the project's correctness claim made checkable by hand: the file this
 * button produces is the same one `tests/tshark-diff.test.ts` compares against
 * Wireshark on every commit.
 */

import { writePcap, type PcapPacket } from '../core/pcap/write.ts'
import type { CompiledTimeline } from '../scenario/compile.ts'

export type ExportPcapButtonProps = {
  timeline: CompiledTimeline
  filename: string
}

export function ExportPcapButton({ timeline, filename }: ExportPcapButtonProps) {
  const download = (): void => {
    const packets: PcapPacket[] = timeline.packets.map((packet, index) => ({
      frame: packet.frame,
      tMs: timeline.marks[index]?.sentMs ?? 0,
    }))

    const blob = new Blob([writePcap(packets) as BlobPart], { type: 'application/vnd.tcpdump.pcap' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = filename
    document.body.append(anchor)
    anchor.click()
    anchor.remove()
    URL.revokeObjectURL(url)
  }

  return (
    <button type="button" className="export-button" onClick={download}>
      Export {filename}
    </button>
  )
}
