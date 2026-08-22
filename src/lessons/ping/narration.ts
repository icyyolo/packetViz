import type { Narration } from '../../scenario/types.ts'

export const pingNarration: Narration = {
  intro:
    'Ping is the smallest useful network program there is: send something, ask for it back, time how long it takes. Everything it can tell you comes from four packets like these — and the two things it depends on, the identifier and the sequence number, are fields you can click on below.',
  steps: [
    {
      title: 'Request — send something back to me',
      body:
        'An echo request is a type, a code, a checksum, two numbers and whatever data the sender felt like including. Look at the data field: thirty-two bytes of alphabet, chosen by the sending program and meaningless to ICMP. Its only job is to come back unchanged, which is what proves the path works at that size and in that direction. Note also what is NOT here: no ports, because ICMP is not carried by a transport and has no notion of a program to deliver to. The identifier is what takes that job on.',
    },
    {
      title: 'Reply — the same message, turned around',
      body:
        'The reply is the request with the type changed from 8 to 0, the addresses swapped and the checksum recomputed. The identifier, the sequence number and every byte of the data are copied back verbatim — RFC 792 requires it. That is the whole trick: ping does not need the other end to understand anything, only to be willing to echo. Compare the two hex dumps and you will find they differ in the type byte, the checksum and the IP header, and nowhere else.',
    },
    {
      title: 'Request — sequence 2',
      body:
        'A second request, one second later, with the sequence number incremented and the identifier unchanged. This is all of ping’s loss detection: if a sequence number never comes back, that request or its reply was dropped, and ping prints nothing for that line. It cannot tell you which of the two directions lost it — a limitation people forget when they read a ping result as "the server is down".',
    },
    {
      title: 'Reply — and the round trip',
      body:
        'The second reply arrives, and the time between the request leaving and this arriving is the round-trip time ping reports. Notice that ICMP carries no timestamp: the sending host measures the interval itself, which is why the number is a property of the sender’s clock and not of the network. Some implementations put a timestamp in the payload data — remember that the payload comes back unchanged, so writing the send time into it means the reply carries it home for you.',
    },
  ],
}
