import type { Narration } from '../../scenario/types.ts'

export const tcpHandshakeNarration: Narration = {
  intro:
    'Three packets, no data, and a connection exists. The handshake is where TCP does the one thing UDP cannot: it gets both ends to agree on where each other’s stream starts, before a single byte of it is sent. Watch the sequence and acknowledgement numbers below — this is the first lesson here where the interesting fact lives between the packets rather than inside one.',
  steps: [
    {
      title: 'SYN — here is where my stream starts',
      body:
        'The client picks a random starting number and announces it. Random, not zero: if it started at zero, a delayed segment from a previous connection between the same four addresses and ports could be accepted as part of this one. This is the only segment of the whole connection with the ACK flag clear, because it is the only one with nothing to acknowledge — which is exactly how a firewall recognises a connection attempt. The options are the connection’s terms, offered once and never repeated: the largest segment it can accept, whether it can do selective acknowledgement, and how far to shift every window size from here on.',
    },
    {
      title: 'SYN-ACK — and here is mine',
      body:
        'One packet doing two jobs: it acknowledges the client’s starting number and announces the server’s own. Look at the acknowledgement number and compare it with the sequence number in the packet above — it is the client’s number plus one. A SYN carries no data but still consumes one sequence number, so that "I have received your SYN" and "I have received your first byte" are different statements. That is the whole reason this exchange needs three packets and not two: the server’s starting number needs acknowledging too.',
    },
    {
      title: 'ACK — agreed',
      body:
        'The client acknowledges the server’s starting number and the connection is open; the next segment either end sends may carry data. Notice this packet has no options — they belonged to the SYN that opened the connection — and that it is short enough for Ethernet to pad it out to sixty bytes, which is the padding field at the end of the hex dump. One thing worth knowing if you also use Wireshark: it shows sequence numbers relative to each side’s starting number, so it prints Seq=0 and Seq=1 here. The field tree below shows the number actually on the wire. Both are true; only one of them is in the packet.',
    },
  ],
}
