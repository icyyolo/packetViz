import type { Narration } from '../../scenario/types.ts'

export const dhcpNarration: Narration = {
  intro:
    'A host that has just been switched on knows its own MAC address and nothing else. No IP address, no subnet mask, no gateway, and no idea whether a server exists to give it any of them. Four broadcast messages later it has all four. Press play, and watch every one of them go to the whole segment — including the printer, which has no interest in any of it.',
  steps: [
    {
      title: 'Discover — a question addressed to everyone',
      body:
        'The client has no address, so it sends from 0.0.0.0 to the limited broadcast address, and the printer receives the frame along with the server. Look at the source and destination ports: 68 to 67, both well known, because a server cannot open a connection back to a host that has no address. The client also sets the broadcast flag in the DHCP header, asking any server that answers to broadcast its reply for the same reason. Option 55 lists what it would like to be told: subnet mask, router, DNS.',
    },
    {
      title: 'Offer — one server answers',
      body:
        'The server proposes an address in the yiaddr field — "your IP address" — and attaches the configuration to go with it: the mask, the gateway, a name server and a lease time in option 51. Nothing is committed yet on either side. If two servers had answered, the client would now be holding two offers, which is why the next message has to name the one it chose.',
    },
    {
      title: 'Request — the client accepts, in public',
      body:
        'Still from 0.0.0.0, still broadcast: the client has not configured the address yet, and it will not until the server confirms. Option 50 says which address it is accepting, option 54 says which server it accepted it from. The broadcast is what makes that second option meaningful — every other server on the segment sees that it was not chosen and can put its own offer back in the pool.',
    },
    {
      title: 'Ack — the lease is real',
      body:
        'The server confirms the same address in yiaddr and repeats the configuration, and only now does the client start using 10.0.0.50. The lease is 86,400 seconds: this is a loan, not a grant, and the client must renew it or lose the address. The diff below sets this packet beside the Request that provoked it: the direction reverses, the ports swap, and the configuration the client asked for arrives filled in. What it also shows is how little of a DHCP message is DHCP — most of those 300 bytes are a fixed BOOTP header from 1985, two thirds of it two string fields nobody fills in.',
    },
  ],
}
