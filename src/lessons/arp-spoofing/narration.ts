import type { Narration } from '../../scenario/types.ts'

export const arpSpoofingNarration: Narration = {
  intro:
    'Same segment, same protocol, one extra host. Alice and Bob do nothing wrong, Mallory sends one unsolicited packet, and Alice ends up sending Bob\'s traffic to Mallory. Watch the cache tables, not the packets — the attack is invisible in any single frame. Press play.',
  steps: [
    {
      title: 'An ordinary lookup',
      body:
        'Alice needs Bob\'s hardware address and asks the whole segment for it. Mallory receives this frame as well; she is not the target, so she discards it. Every cache on the segment is still empty.',
    },
    {
      title: 'Bob answers, Alice caches him',
      body:
        'Bob replies with his real hardware address and Alice installs the mapping. This is the correct entry — note the packet number and timestamp beside it, because you are about to watch them change.',
    },
    {
      title: 'A legitimate announcement',
      body:
        'Bob broadcasts an unsolicited reply about himself: sender and target IP address are the same, which is what makes it gratuitous. A host does this after a reboot, an address change, or a failover, so that neighbours holding a stale entry refresh it. Alice already has an entry, so she refreshes it. Mallory does not, and RFC 826 says she must not create one from a conversation she merely overheard. The mechanism is doing exactly its job.',
    },
    {
      title: 'The same mechanism, abused',
      body:
        'Mallory sends Alice a reply to a question Alice never asked, carrying Bob\'s IP address and Mallory\'s hardware address. Compare it byte for byte with packet 2: same layout, same opcode, valid in every particular. RFC 826 says that if the sender IP is already in the table, update it — with no check that a request was made, and no way to check the sender is who it claims. Alice\'s entry for 10.0.0.2 now points at Mallory, and everything Alice sends to Bob goes to Mallory\'s interface first. Nothing here is malformed — every field is exactly the width and shape the RFC specifies, and no dissector can reject it. What Wireshark does raise is a warning of a different kind: "Duplicate IP address configured (10.0.0.2)", because its ARP dissector remembers the earlier packets and notices that one IP address just changed hardware address. That is the shape of every real defence against this — detection needs history, because no single frame is wrong. The protocol has no field in which authenticity could even be expressed — which is why the fix is not in ARP but around it: static entries, DHCP snooping with dynamic ARP inspection, or a switch port-security policy.',
    },
  ],
}
