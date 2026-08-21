import type { Narration } from '../../scenario/types.ts'

export const arpNarration: Narration = {
  intro:
    'Alice wants to send an IP packet to 10.0.0.2. She knows the IP address, but an Ethernet frame is addressed by MAC address, and she does not know Bob\'s. Nothing can leave her interface until she does. Press play.',
  steps: [
    {
      title: 'Alice asks the whole segment',
      body:
        'Alice cannot address the question to Bob — finding Bob\'s address is the question. So she sends it to the broadcast MAC, ff:ff:ff:ff:ff:ff, and every interface on the segment accepts it. Carol receives this frame too; she reads the target IP, sees it is not hers, and drops it. Note the target MAC in the request: all zeros. That field is the hole in Alice\'s knowledge, sent as a literal blank.',
    },
    {
      title: 'Bob answers, and only Bob',
      body:
        'Bob recognises his own IP in the target field and replies. His reply is unicast, addressed straight back to the MAC Alice put in the sender field — the request carried the return address with it, so no second lookup is needed. Compare the two packets byte for byte: they have identical 28-byte layouts, and only the opcode and the four address fields differ. Everyone who saw the request also learned Alice\'s mapping from it, cached without being asked. That is what makes ARP spoofable.',
    },
  ],
}
