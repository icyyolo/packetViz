# Architecture

PacketViz shows one packet at four levels of abstraction — the segment, the
ladder, the decoded field tree, the hex dump — and links the last two in both
directions. This document is about the decisions that made that possible, and
the ones that were rejected.

## The invariant

> **There is exactly one source of truth per packet: a `Uint8Array` produced by
> an encoder written against the wire format. All four layers are decodes or
> projections of that buffer.**

Not a style preference. It is what separates this from an educational website
with a nice diagram: if a TTL, a port, a flag or a DHCP option code were stored
anywhere other than the bytes, then the picture and the packet could disagree,
and no test could tell you which one was lying.

The encoders need inputs, and that is where the line has to be drawn explicitly:

* A **scenario file** holds scene intent only — who is on the segment, their
  addresses, the propagation delay, event ordering, lease parameters, prose.
* **Every protocol fact on screen** — opcode, checksum, port, option 53's
  value — is read back out of the buffer by `decodeFrame()`.

Three mechanisms keep it that way, none of which rely on anybody remembering:

1. **A lint rule.** `.oxlintrc.json` forbids anything under `src/views/**` from
   importing `src/lessons/**`. The four layer components accept a
   `DecodedPacket` and nothing else, so a view *cannot* read a scenario. Prose
   reaches the UI through `src/ui/LessonShell.tsx`, which is outside the
   restricted path.
2. **A grep test.** `tests/scenario.test.ts` fails if a protocol constant — an
   EtherType, an option code, the DHCP magic cookie — appears in a lesson file.
   Addresses and lease times are allowed; they are scene intent.
3. **A writable hex grid.** Layer 4 is editable. Typing a byte produces a new
   buffer, the frame is decoded again from scratch, and all four layers move —
   including the ladder's labels and the exported `.pcap`. If any layer held its
   own copy of a fact, that copy would visibly fail to follow the edit. The
   invariant is falsifiable in about five seconds.

An imported capture is the same story with the scenario removed entirely: the
hosts on the ladder are derived from the Ethernet addresses in the frames, and
their labels from IP headers inside them. Nobody types a host list for a
stranger's file.

## The codec split: declarative decode, imperative encode

Each fixed-layout header is a `FieldSpec` table — id, name, width in bits, a
renderer, a description and an RFC citation — and a generic runner walks it,
emitting `FieldNode`s with **absolute** byte offsets. Encoders are hand-written
`ByteWriter` code against the same wire constants.

Two obvious alternatives were rejected:

* **One bidirectional spec that both encodes and decodes.** Tempting, and wrong
  for this project. A decoder must handle a lying length field, a truncated
  frame and an option whose length is zero; an encoder must compute a checksum
  over bytes it has already written, and pad a frame to 60 bytes. A single
  description that covers both ends up as a description of neither, full of
  escape hatches. Keeping them apart means each is honest about its own job —
  and the two directions are reconciled by **round-trip property tests** over
  1,000 generated exchanges, which is a stronger check than shared code would
  have been, because it can fail.
* **A declarative description of everything.** DHCP's option list is a
  hand-written TLV loop, because a variable-length list of variable-length items
  with a termination rule and adversarial inputs is a parser, not a table. It
  still emits ordinary `FieldNode`s, so nothing downstream knows the difference.

Absolute offsets are what make the signature feature trivial. Every decoder is
`(frame, offset) -> nodes with absolute spans`, so a field's byte range *is* a
range of hex cells; selection stores field **ids**, and spans are re-derived on
every render, which is why a selection survives a re-decode after a hex edit.

## The decoder is a total function

`decodeFrame` is total. For **any** `Uint8Array`, including empty, truncated or
adversarial input, it:

1. never throws — it returns what it could parse, plus a `Problem`;
2. never loops forever — every variable-length loop advances by at least one
   byte per iteration or bails with a `Problem` (a zero-length DHCP option is
   the concrete trap);
3. never allocates unbounded — no allocation is sized from an untrusted length
   field without clamping it to the remaining buffer;
4. never reads out of bounds — undecodable trailing bytes become one raw
   `FieldNode`, not a crash.

This is not defensive polish. Layer 4 is writable and Phase 7 opens files this
project did not write; both are ways for a human to point the decoder at
garbage. `tests/fuzz.property.test.ts` enforces all four clauses over thousands
of generated cases plus named adversarial ones, and removing a single bounds
check makes it fail. `readPcap` obeys the same contract at the file level: a
malformed capture is a returned message, never an exception.

## Wireshark is the oracle

A decoder tested against its own encoder proves only that two halves of one
mind agree. So every commit writes a real `.pcap`, hands it to `tshark`, and
asserts two things: that Wireshark finds nothing malformed at error severity,
and that for **every leaf field we emit**, Wireshark read the same value out of
the same bytes. A coverage assertion fails the build if a newly decoded field
has no entry in the mapping table, so nothing escapes verification by being new.

Comparison is against `node.raw` — the bytes — not our rendered strings, so the
test measures agreement about the wire format rather than about formatting. The
mapping table is written out explicitly rather than assumed to be identity,
because the places where the two models differ are the interesting ones, and
each is pinned with the reason:

* Wireshark ships with IPv4 and UDP checksum validation **off**; the test turns
  it on and requires status `Good`, not "unchecked".
* `ip.hdr_len` and `ip.frag_offset` are reported in bytes, scaled from their
  wire units; `ip.flags` is reported as the whole byte, fragment-offset bits
  included.
* tshark reports the DHCP End option's `dhcp.option.type` as `0` while its own
  detail tree prints `255`.
* Wireshark reserves "padding" for bytes that brought a short frame up to the
  60-byte minimum and calls anything else a **trailer** — a distinction our own
  encoders could never have surfaced, since they always pad to exactly 60. A
  hand-typed foreign frame found it.

The oracle has repeatedly decided design questions that would otherwise have
been settled by opinion, which is the whole reason it is in CI rather than in a
README.

## Why not Rust or WASM

There is no performance problem: the largest thing decoded is a few hundred
bytes, and an imported capture is walked at 16 bytes per record. The cost would
be real — marshalling field spans across the boundary on every render, a second
toolchain in CI, and a build step between a code change and seeing it — and the
benefit would be a claim rather than a capability. The interesting engineering
here is the invariant, the totality contract and the differential test, none of
which get easier in another language.

## Layout

```
src/core/        bytes, field types, spec runner, checksums, registry, pcap read/write
src/core/protocols/   ethernet, arp, ipv4, udp, dhcp — specs + encoders + decoders
src/scenario/    scene intent types, scenario -> timeline, capture -> timeline
src/timeline/    the virtual clock; every view is f(t)
src/views/       the four layers (may not import lessons — enforced by lint)
src/ui/          shells, transport controls, import, export
src/pages/       routes, concept map, generated reference and header diagrams
src/lessons/     scenarios and prose, no protocol facts
tests/           unit, property, fuzz and Wireshark differential
e2e/             Playwright: routes, the exhaustive field<->byte sweep, hex editing
```
