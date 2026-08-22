import type { Narration } from '../../scenario/types.ts'

export const dnsNarration: Narration = {
  intro:
    'Two datagrams, and a name becomes an address. DNS is worth reading byte by byte for one reason above all the others: it is the protocol in this project where a field’s value is not in the field. Look at the answer’s name in the second packet — two bytes that mean "the name I already sent you".',
  steps: [
    {
      title: 'Query — a name, in pieces',
      body:
        'There are no dots on the wire. A name is a series of length-prefixed labels ending in a zero byte, so files.corp.internal travels as 5 f i l e s 4 c o r p 8 i n t e r n a l 0 — click the name field and read it out of the hex dump yourself. The dots you type are label boundaries, which is also why a label cannot exceed 63 bytes: two bits of that length byte were reserved from the start for something else, and the next packet is what they were reserved for. Note the recursion-desired flag: this client is a stub resolver, and it is asking the server to do all the actual work.',
    },
    {
      title: 'Response — the same question, plus an answer',
      body:
        'The answer repeats the question verbatim — that is how the client knows what was answered — and then adds a record. The record’s name field is two bytes: 0xC00C. The two high bits set mark it as a pointer, and the remaining fourteen say "offset 12 from the start of this message", which is where the question’s name begins. The field tree shows files.corp.internal because the decoder followed the pointer, but those bytes do not contain it, and a decoder that trusted them to would be reading somebody else’s memory. Nothing in the format stops a pointer pointing at itself, which is why this decoder tracks the offsets a name has already visited and refuses to go round twice. The time to live is 300 seconds: the client may reuse this answer for five minutes, and nothing can revoke it in the meantime.',
    },
  ],
}
