# PacketViz — Implementation Plan

> **Status:** approved 2026-08-21. This file is the source of truth for the
> build. Update it as phases complete.

## Context

An interactive networking-concepts site built as a portfolio piece for technical
interviewers. The audience judges engineering depth, not content volume, so the
project is deliberately narrow: **two protocols, done to the byte.**

The product idea is *semantic zoom*: one packet, viewed at four levels of
abstraction, with a bidirectional link between the decoded field tree and the raw
hex dump. Click `TTL` in the tree, its bytes light up in hex; click a byte, its
field lights up in the tree.

The architectural constraint that makes it a systems project rather than an
educational website:

> **There is exactly one source of truth per packet: a real `Uint8Array` produced
> by an encoder written against the wire format. All four layers are decodes or
> projections of that buffer.**

The correctness anchor: any lesson can export its packets as a real `.pcap` that
Wireshark opens cleanly and decodes to the same values our own decoder shows.
This is enforced in CI by a differential test against `tshark`.

### Decisions already settled

| Question | Decision |
|---|---|
| Stack | Vite + React 19 + TypeScript (strict). Static SPA. |
| Backend | None. Everything is deterministic client-side; export is a Blob, import is the File API. |
| Codec language | TypeScript only. No Rust/WASM — no perf need, and field-span marshalling across the boundary would cost more than it proves. |
| Animation | Deterministic virtual clock; every view is `f(t)`. Scrubbable. SVG rendering. CSS transitions only for non-timeline UI polish. |
| Authoring | Typed TS scenario modules. No MDX, no JSON, no CMS. |
| Codec structure | Spec-driven decoder + imperative encoder + shared field-id constants, reconciled by round-trip property tests. |
| Testing | Vitest + fast-check property tests + `tshark` differential test + Playwright E2E, all in CI. |
| Decoder contract | Hostile-input safe: `decode()` never throws, never loops forever, never allocates unbounded. Proven by a fuzz test in CI. |
| Hex editing | Layer 4 is writable — edit a byte, everything re-decodes live. This is the demonstration of the single-buffer invariant. |
| URL state | Selection syncs to the URL down to the field: `#/lesson/dhcp?p=2&f=dhcp.opt.53`. |
| Accessibility | Keyboard navigation through hex grid and field tree; highlight never depends on hue alone. |
| Import limits | Lazy decode (record headers on load, packet decoded on selection), hard cap ~5,000 packets. |
| Field explainers | `description` + RFC reference live in the `FieldSpec` tables, next to the definition that drives decoding. Shared by field tree, detail panel and reference page. |
| Reference page | `#/reference/:protocol` — generated from the specs: RFC-style header diagram, field table, value dictionaries, and a "see it live" deep link per field. |
| Docs | `ARCHITECTURE.md` (~1 page) + README with Playwright-generated screenshots and one GIF. |
| Repo | Local dir `/home/mx/packetviz` (lowercase, WSL-native filesystem); GitHub remote `icyyolo/packetViz`. The two need not match — but `base` in `vite.config.ts` must match the **GitHub** name's case exactly, or every Pages asset 404s. |
| Hosting | GitHub Pages via GitHub Actions. |
| Routing | `react-router-dom` with `HashRouter` — deep-linkable lesson URLs, no Pages 404.html hack. |
| Home page | Lesson cards + a concept map **generated from the protocol registry**, so it doubles as an honest implemented/not-implemented status view. Map lands in Phase 8, after the registry is real. |
| Build order | ARP first (walking skeleton), then DHCP (flagship), then pcap import. |

### Scope boundaries (explicit non-goals)

No accounts, auth, progress tracking, database, backend, CMS, live capture from a
real NIC, mobile app, or plugin architecture for protocols beyond Ethernet / ARP /
IPv4 / UDP / DHCP.

**Topology layer is a static scene, not a simulator.** For a single L2 segment
with three hosts there is nothing to simulate. Propagation delay is a per-lesson
scene constant used to position the packet dot. There is no loss model, no
queueing, no congestion. DHCP retransmission, if ever added, is a scripted
scenario event — not emergent behaviour.

---

## The single-source-of-truth invariant

The encoder needs inputs. That is not a violation, but the line must be explicit
or the design will drift:

- **The scenario file holds scene intent only:** host list, MAC/IP addresses,
  lease parameters, event ordering, timings, narration prose.
- **Every displayed protocol fact** — opcode, TTL, port, flag, DHCP option 53
  value, checksum — is read back out of the buffer by `decode()`. Never from the
  scenario.

**Mechanical enforcement:** an ESLint `no-restricted-imports` rule forbids
anything under `src/views/**` from importing `src/lessons/**`. The four layer
components accept only `Uint8Array` + `DecodedPacket`. Narration prose reaches the
UI through `src/ui/LessonShell.tsx`, and lesson metadata through
`src/pages/HomePage.tsx` — both outside the restricted path.

`src/lessons/index.ts` holds `LessonMeta { slug, title, blurb }` only. Anything a
card displays that is protocol-derived — packet count, the protocol badges — is
computed by compiling the scenario and reading the decode, never typed by hand.

---

## Repository layout

```
/home/mx/packetviz                  # local dir; GitHub remote is icyyolo/packetViz
├── PLAN.md                        # this file
├── README.md
├── ARCHITECTURE.md
├── playwright.config.ts
├── docs/media/                    # generated screenshots + demo.gif
├── package.json
├── vite.config.ts                 # base: '/packetViz/'  (must match repo name case)
├── tsconfig.json                  # strict: true
├── vitest.config.ts
├── .oxlintrc.json                 # holds the invariant rule (overrides block)
├── .github/workflows/ci.yml       # test + tshark
├── .github/workflows/deploy.yml   # build + deploy-pages
├── src/
│   ├── main.tsx
│   ├── App.tsx
│   ├── core/
│   │   ├── bytes.ts               # ByteWriter / ByteReader over DataView
│   │   ├── field.ts               # FieldNode, DecodedPacket types
│   │   ├── spec.ts                # FieldSpec table type + sequential runner
│   │   ├── checksum.ts            # RFC 1071 + UDP pseudo-header
│   │   ├── registry.ts            # etherType / ipProto / port dispatch
│   │   ├── format.ts              # MAC, IPv4, hex renderers
│   │   ├── protocols/
│   │   │   ├── ethernet.ts
│   │   │   ├── arp.ts
│   │   │   ├── ipv4.ts
│   │   │   ├── udp.ts
│   │   │   └── dhcp.ts
│   │   └── pcap/
│   │       ├── write.ts
│   │       └── read.ts
│   ├── scenario/
│   │   ├── types.ts               # Scenario, Host, PacketEvent
│   │   └── compile.ts             # Scenario -> CompiledTimeline
│   ├── timeline/
│   │   ├── clock.ts               # rAF virtual clock: play/pause/seek/rate
│   │   └── useTimeline.ts
│   ├── views/                     # RESTRICTED: may not import src/lessons
│   │   ├── TopologyView.tsx       # layer 1
│   │   ├── FlowView.tsx           # layer 2 (ladder diagram)
│   │   ├── FieldTreeView.tsx      # layer 3
│   │   ├── HexView.tsx            # layer 4
│   │   ├── FieldDetailPanel.tsx   # explainer, driven by selection
│   │   └── SelectionContext.tsx   # { packetIndex, selectedSpan }
│   ├── ui/
│   │   ├── LessonShell.tsx
│   │   ├── Scrubber.tsx
│   │   ├── ExportPcapButton.tsx
│   │   └── ImportPcapDropzone.tsx
│   ├── pages/
│   │   ├── HomePage.tsx           # concept map + lesson cards
│   │   ├── LessonPage.tsx         # :slug -> lesson
│   │   ├── ImportPage.tsx
│   │   ├── ReferencePage.tsx      # :protocol -> generated from FieldSpec
│   │   ├── HeaderDiagram.tsx      # RFC-style 32-bit box drawing, derived
│   │   └── ConceptMap.tsx         # SVG, derived from core/registry.ts
│   └── lessons/
│       ├── index.ts               # LessonMeta[] registry (slug/title/blurb)
│       ├── arp/{scenario.ts,narration.ts}
│       └── dhcp/{scenario.ts,narration.ts}
├── scripts/
│   └── capture-media.ts           # drives Playwright to regenerate docs/media
├── tests/
│   ├── ethernet.test.ts  arp.test.ts  ipv4.test.ts  udp.test.ts  dhcp.test.ts
│   ├── checksum.test.ts
│   ├── roundtrip.property.test.ts
│   ├── fuzz.property.test.ts      # decoder hostile-input contract
│   ├── pcap.test.ts
│   └── tshark-diff.test.ts
└── e2e/
    ├── field-byte-link.spec.ts    # exhaustive, replaces manual criterion #4
    ├── hex-edit.spec.ts
    └── smoke.spec.ts
```

---

## Core types

```ts
// src/core/field.ts
export type FieldNode = {
  id: string;              // stable dotted path, e.g. "eth.dst", "dhcp.opt.53"
  name: string;            // "Destination MAC address"
  byteStart: number;       // ABSOLUTE offset within the frame
  byteLength: number;
  bitOffset?: number;      // sub-byte fields (IPv4 version/IHL, flags)
  bitLength?: number;
  raw: Uint8Array;
  value: string;           // human-rendered
  description?: string;    // teaching text, NOT a protocol fact
  children?: FieldNode[];
};

export type DecodedPacket = {
  frame: Uint8Array;
  tree: FieldNode[];       // Ethernet -> ARP | IPv4 -> UDP -> DHCP
  summary: string;         // derived, e.g. "ARP Request 10.0.0.1 -> 10.0.0.2"
  problems: Problem[];     // truncation, lying length fields, unknown protocol
};

export type Problem = {
  severity: 'error' | 'warning';
  message: string;         // "DHCP option 51 length 8 exceeds remaining 3 bytes"
  byteStart: number;
  byteLength: number;      // so problems highlight in hex like any field
};
```

### The decoder contract (enforced by fuzz tests)

`decode()` is a **total function**. For *any* `Uint8Array`, including empty,
truncated, or adversarial input, it:

1. **never throws** — it returns whatever it could parse plus a `Problem`;
2. **never loops forever** — every TLV/option loop must advance by at least one
   byte per iteration or bail with a `Problem` (a zero-length DHCP option is the
   concrete trap);
3. **never allocates unbounded** — no allocation is sized from an untrusted length
   field without first clamping it to the remaining buffer;
4. **never reads out of bounds** — every read is bounds-checked, and undecodable
   trailing bytes become a single raw `FieldNode`, not a crash.

This is not defensive polish. Phase 7 imports files the user did not create.

Absolute offsets are what make layer 3 ↔ layer 4 linking trivial: every decoder
takes `(frame, offset)` and emits absolute spans. Sub-byte fields highlight their
containing byte(s) in hex and show the bit range in the tree.

```ts
// src/core/spec.ts — one table per protocol, drives decode AND all explainer UI
export type FieldSpec = {
  id: string;
  name: string;
  bits: number;                       // sub-byte fields supported
  render: (raw: Uint8Array, ctx: DecodeCtx) => string;
  description: string;                // shown in detail panel + reference page
  reference?: string;                 // e.g. "RFC 826 §2", "RFC 2131 §2"
  values?: Record<number, string>;    // enum dictionary: opcodes, option codes
};
```

The `description`, `reference` and `values` fields exist so there is exactly one
place a field is explained. The field tree, the detail panel and the generated
reference page all read this table — none of them own prose about a field.

**Codec split (honest about where declarative breaks down):** `spec.ts` runs a
fixed-layout field table and covers Ethernet, ARP, IPv4, UDP and the BOOTP fixed
header. DHCP's TLV option list is a hand-written loop that still emits
`FieldNode`s. Encoders are hand-written `ByteWriter` code that imports the same
field-id constants. The two directions are reconciled by round-trip property
tests, not by a framework.

---

## Phases

Every step below has a command to run and an expected result.

### Phase 0 — Scaffold, CI, and a live URL

| # | Step | Verify |
|---|---|---|
| 0.1 | `git init`; `PLAN.md` at repo root; GitHub repo `icyyolo/packetViz` | `git log --oneline` shows initial commit |
| 0.2 | `npm create vite@latest . -- --template react-ts`; set `strict: true`, `base: '/packetViz/'` (case must match the repo name or every asset 404s) | `npm run build` exits 0, `dist/` produced |
| 0.3 | Add Vitest + fast-check; a trivial passing test | `npm test` → 1 passed |
| 0.4 | `.oxlintrc.json` `overrides`: `no-restricted-imports` blocking `**/lessons/**` for `src/views/**` (oxlint ships with the Vite template and implements this ESLint rule) | Temporarily add such an import → `npm run lint` fails; remove it → passes |
| 0.5 | `.github/workflows/ci.yml`: node 22, `npm ci`, lint, test. Install tshark non-interactively:<br>`echo "wireshark-common wireshark-common/install-setuid boolean false" \| sudo debconf-set-selections`<br>`sudo DEBIAN_FRONTEND=noninteractive apt-get install -y tshark` | Push → Actions run green; log shows a `tshark` version line |
| 0.6 | `.github/workflows/deploy.yml` using `actions/upload-pages-artifact` + `actions/deploy-pages`; enable Pages (source: Actions) | `curl -sI https://icyyolo.github.io/packetViz/` → `HTTP/2 200` |
| 0.7 | Local: `sudo apt install tshark` | `tshark -v` prints version |

**Phase 0 done when:** a placeholder page is live at the Pages URL and CI is green.

### Phase 1 — Byte core, Ethernet, ARP codec

| # | Step | Verify |
|---|---|---|
| 1.1 | `src/core/bytes.ts`: `ByteWriter` (u8/u16be/u32be/bytes/zeros) and `ByteReader` over `DataView` | `npm test` — writer produces expected hex for a hand-checked sequence |
| 1.2 | `src/core/field.ts`, `src/core/spec.ts`: `FieldSpec` table type + sequential runner emitting absolute-offset `FieldNode`s | Unit test: a 3-field toy spec over 6 bytes yields correct `byteStart`/`byteLength` |
| 1.3 | `src/core/protocols/ethernet.ts`: `encodeEthernet({dst,src,etherType,payload})` + spec-driven decode. Pad frames to the 60-byte minimum and expose the padding as its own `FieldNode` | `tests/ethernet.test.ts`: encoded 42-byte ARP frame is 60 bytes; decode finds `eth.dst`/`eth.src`/`eth.type` at offsets 0/6/12 |
| 1.4 | `src/core/protocols/arp.ts`: `encodeArp({op,senderMac,senderIp,targetMac,targetIp})` (htype 1, ptype 0x0800, hlen 6, plen 4) + decode | `tests/arp.test.ts`: request opcode 1 at offset 20; full 28-byte payload matches a hand-written hex literal |
| 1.5 | `tests/roundtrip.property.test.ts`: fast-check generators for MAC/IPv4/opcode; assert `decodeArp(encodeArp(x))` field values equal `x` | `npm test` → 1000 cases pass |
| 1.6 | `tests/fuzz.property.test.ts`: fast-check `uint8Array` generators (arbitrary bytes; valid frames truncated at every offset; valid frames with one byte mutated). Assert the four contract clauses, with each case wrapped in a wall-clock timeout to catch hangs | `npm test` → 5000 cases, zero throws, zero timeouts. Then temporarily remove one bounds check → the fuzz test fails |

**Phase 1 done when:** `npm test` is green, no ARP field value exists outside the
encoder's byte output, and the decoder survives garbage.

> **Status: complete (2026-08-21, commit `49b3fb9`).** 36 tests green across 7
> files: 1000-case round-trip, 5500-case fuzz. Removing the bounds check in
> `runSpec` fails 3 of the 5 fuzz tests, so 1.6 bites. Three deviations recorded:
> field ids use tshark's names (`eth.dst`, `arp.opcode`, `arp.src.hw_mac`) so the
> Phase 2 mapping table is near-identity; `src/core/registry.ts` was built now
> rather than in Phase 8 because Ethernet-to-ARP dispatch needs it, and its
> EtherType table is the seed of 8.1's derived `implemented` flag; `ByteReader`
> has no production caller until Phase 4's DHCP option loop and Phase 7's pcap
> reader. Clause 2 of the decoder contract ("never loops forever") is enforced by
> a per-case elapsed-time budget plus an explicit test timeout, not a true
> per-case timeout — Phase 1 has no loop over untrusted data, so the real test of
> that clause arrives with the DHCP TLV loop in 4.8.

### Phase 2 — pcap export and the tshark differential test

| # | Step | Verify |
|---|---|---|
| 2.1 | `src/core/pcap/write.ts`: classic pcap — global header magic `0xa1b2c3d4`, v2.4, thiszone 0, sigfigs 0, snaplen 65535, network 1 (LINKTYPE_ETHERNET); per-record `ts_sec/ts_usec/incl_len/orig_len`. Timestamps = fixed epoch constant (`2026-01-01T00:00:00Z`) + scenario event offset, so output is byte-identical every run | `tests/pcap.test.ts`: 2-packet file length = `24 + 2*(16+60)`; SHA-256 of output is stable across runs |
| 2.2 | `tests/tshark-diff.test.ts` helper: write pcap to a temp path, `execFile('tshark', ['-r', f, '-T', 'json'])`, parse | Test run prints tshark's packet count = 2 |
| 2.3 | Assertion A — structural validity: `tshark -r f.pcap -T fields -e _ws.expert.severity` | Every line empty → no malformed packets, no bad checksums |
| 2.4 | Assertion B — field equality: an explicit per-protocol mapping table (`eth.dst`→`eth.dst`, `arp.opcode`→`arp.opcode`, …) comparing normalised values for every leaf field our decoder emits. The test also asserts the mapping table **covers** every emitted leaf id, so a new field cannot silently escape verification | `npm test` → all mapped fields equal; deliberately corrupt one encoder byte → test fails |
| 2.5 | Skip-guard: tshark tests skip with a loud warning if `tshark` is absent, unless `REQUIRE_TSHARK=1` (set in CI) | `PATH= npm test` → skipped; CI → runs |

**Phase 2 done when:** CI proves, on every commit, that our decoder and Wireshark
agree field-for-field on generated ARP traffic.

> **Status: complete (2026-08-21).** 51 tests green across 9 files. tshark 3.6.2
> compares 26 field values across 2 packets; the mapping table covers all 13 leaf
> field ids the decoder emits, with zero exceptions. Every Phase 1 field id turned
> out to match tshark's name exactly, `eth.padding` included, but the table is
> still written out explicitly — DHCP will diverge (`dhcp.opt.53` vs tshark's
> `dhcp.option.dhcp`), and an explicit table makes a rename on either side fail
> loudly instead of silently skipping a field.
>
> Two things worth carrying forward:
>
> - **Comparison is against `node.raw`, not our rendered display string.** The
>   test asks whether Wireshark and our decoder read the same bytes the same way,
>   not whether we format them the same way.
> - **Assertion A is a weaker oracle than the plan assumed.** Corrupting the
>   encoder's `hlen` from 6 to 7 produced a file tshark dissects with *no* expert
>   info at all — it obediently reads 7-byte hardware addresses and reports
>   "Who has 0.2.0.0? Tell 0.0.1.0". Structural validity alone would have passed
>   it. Assertion B caught it, along with the reverse-coverage check. Read: the
>   field-equality table is the load-bearing assertion, and expert-info is a
>   cheap extra, not the proof.
>
> Verified by deliberate breakage: swapping two spec entries fails B with
> `packet 0, field arp.hw.size vs tshark arp.hw.size: expected '4' to be '6'`;
> removing tshark from `PATH` skips 7 tests with a stderr warning; adding
> `REQUIRE_TSHARK=1` turns that skip into a failure (CI sets it).
>
> One scaffold change was needed: the new tests import node builtins
> (`node:crypto`, `node:child_process`), which `tsconfig.app.json` cannot see
> because its `types` is `["vite/client"]`. Tests moved to their own
> `tsconfig.test.json` (`types: ["node"]`, referenced from `tsconfig.json`), so
> `npm run build` still typechecks them without leaking node globals into the
> browser build.

### Phase 3 — Timeline, the four views, ARP lesson

| # | Step | Verify |
|---|---|---|
| 3.0 | `react-router-dom` with `HashRouter`: `/` → `HomePage`, `/lesson/:slug` → `LessonPage`, `/import` → `ImportPage`, `/reference/:protocol` → `ReferencePage` (added in Phase 8). `src/lessons/index.ts` exports `LessonMeta[]`. Home is a plain card grid for now — packet count and protocol badges derived by compiling each scenario | `npm run dev`, visit `#/lesson/arp` directly → lesson loads; browser back button returns to `/`; an unknown slug shows a not-found message, not a blank screen |
| 3.1 | `src/scenario/types.ts`: `Scenario { hosts, linkDelayMs, events: PacketEvent[] }` where `PacketEvent = { tMs, from, to, build: () => Uint8Array }` | `tsc --noEmit` passes; type has no protocol-field members |
| 3.2 | `src/scenario/compile.ts`: `Scenario -> CompiledTimeline { packets: DecodedPacket[], marks }` — calls `build()` then `decode()` once | Unit test: ARP scenario compiles to 2 `DecodedPacket`s |
| 3.3 | `src/timeline/clock.ts`: rAF-driven virtual clock exposing `t`, `play/pause/seek/setRate`; pure `f(t)` consumers | Unit test: `seek(1200)` then read `t` → 1200, no rAF needed |
| 3.4 | `src/views/SelectionContext.tsx`: `{ packetIndex, selectedSpan: {start,length} | null }` | — |
| 3.5 | `HexView.tsx`: 16-bytes-per-row hex + ASCII; byte cells highlight when inside `selectedSpan`; clicking a byte sets selection | `npm run dev` — click byte 20 of the ARP frame; field tree highlights `arp.opcode` |
| 3.6 | `FieldTreeView.tsx`: collapsible tree from `DecodedPacket.tree`; hover/click sets `selectedSpan` from the node's absolute offsets | Click `eth.src` → hex bytes 6–11 highlight |
| 3.6b | `FieldDetailPanel.tsx`: driven by selection (mouse **or** keyboard), shows name, byte offset, size, decoded value, `description`, `reference`, and the matching entry from `values` when the field is enumerated. Hover previews the same content without stealing selection. Wired with `aria-describedby`, not a hover-only tooltip | Keyboard-navigate to `arp.opcode` → panel reads "Operation … 1 = Request (RFC 826 §2)". Unit test: every leaf field spec has a non-empty `description`, so a new field cannot ship unexplained |
| 3.7 | `FlowView.tsx`: SVG ladder — one lifeline per host, one arrow per event at `y = f(tMs)`; playhead line at current `t`; click an arrow → selects that packet | Scrub the timeline; playhead tracks, arrows below it are dimmed |
| 3.8 | `TopologyView.tsx`: static SVG nodes/link; packet dot at `f(t)` using `linkDelayMs` | Dot travels A→B over exactly `linkDelayMs` |
| 3.9 | `Scrubber.tsx` + `LessonShell.tsx`: play/pause/step, drag playhead, narration text bound to timeline marks | Drag the scrubber; all four layers update together |
| 3.10 | `src/lessons/arp/scenario.ts`: Host A `10.0.0.1 / aa:bb:cc:00:00:01`, Host B `10.0.0.2 / aa:bb:cc:00:00:02`; request broadcast to `ff:ff:ff:ff:ff:ff`, reply unicast | Page renders both packets; **grep the scenario file for `0x0806`, `"1"`, `opcode` → no protocol-field literals** |
| 3.11 | `ExportPcapButton.tsx`: Blob download of the compiled timeline | Download `arp.pcap`, open in Wireshark GUI → 2 packets, no red rows |
| 3.12 | URL state: selection syncs to `?p=<index>&f=<fieldId>` (replace, not push, so the back button escapes the lesson rather than unwinding clicks). Loading such a URL restores packet, selected field and scrubber position | Select `arp.opcode` in packet 2, copy the URL, open in a fresh tab → same field selected, same bytes highlighted. An unknown `f=` value selects nothing instead of erroring |
| 3.13 | Accessibility: hex grid is a roving-tabindex grid (arrow keys move byte to byte, Enter selects); field tree uses ARIA `tree`/`treeitem` with up/down/left/right; highlight uses a colorblind-safe hue **plus** a non-color cue (outline + underline) so it never depends on hue alone | Navigate from byte 0 to byte 20 and select it using only the keyboard; field tree highlights `arp.opcode`. Force greyscale rendering in devtools → selection is still unambiguous |

**Phase 3 done when:** the ARP lesson satisfies the lesson definition of done
below.

> **Status: complete (2026-08-21), 3.0 through 3.13.** Phase 3.5 (live hex
> editing) is not started. 90 tests green across 13 files, lint clean, build
> clean.
>
> Six deviations, all deliberate:
>
> 1. **Selection stores field ids, not byte spans.** 3.4 specified
>    `{ packetIndex, selectedSpan }`; the implementation stores
>    `{ packetIndex, selectedFieldId, hoveredFieldId }` and derives the span from
>    the current decode via `spanOf()`. A stored span goes stale the moment the
>    buffer is re-decoded, which is exactly what Phase 3.5 does on every
>    keystroke, and it makes a deep link carry `?f=arp.opcode` instead of a pair
>    of magic numbers.
> 2. **The ARP frame builders moved into `core`.** `buildArpRequestFrame` and
>    `buildArpReplyFrame` live in `src/core/protocols/arp.ts`. That a request is
>    broadcast, that its target hardware address is all zeros, that the EtherType
>    is ARP — all protocol facts, and leaving them in the scenario would have
>    failed lesson criterion #7. The scenario now contains three host records,
>    one link delay and two timestamps, and nothing else.
> 3. **A third host.** 3.10 named Alice and Bob; Carol (10.0.0.3) was added.
>    Broadcast is invisible with two hosts, and Carol receiving the request and
>    dropping it is the point of the first narration step. She transmits nothing,
>    so the capture is still two packets and byte-identical to Phase 2's.
> 4. **`FieldNode` gained `valueName`.** 3.6b requires the panel to show "the
>    matching entry from `values`"; the runner now copies that entry onto the
>    node, so views never need to reach back into the spec tables.
> 5. **jsdom + @testing-library added as devDependencies.** The plan defers all
>    UI testing to Playwright in Phase 6, which would have left 3.5, 3.6, 3.12
>    and 3.13 verified by "run the dev server and look". `tests/link.dom.test.tsx`
>    and `tests/lesson-page.dom.test.tsx` check them mechanically instead. Phase
>    6's exhaustive cross-lesson sweep still stands; this is a floor, not a
>    replacement.
> 6. **`views/selection.ts` split from `views/SelectionContext.tsx`.** oxlint's
>    `react/only-export-components` warns when a file exports both a component
>    and helpers. The provider is alone in the `.tsx`; the context, hook and pure
>    helpers live in the `.ts`.
>
> Verified: the field-to-byte round trip is machine-checked over **every leaf
> field** of the request packet, both directions, in `link.dom.test.tsx`;
> keyboard navigation reaches byte 20 from byte 0 with `ArrowDown` then four
> `ArrowRight` and selects `arp.opcode` with Enter; `#/lesson/arp?p=1&f=arp.opcode`
> restores the packet, the field, the highlighted bytes and the scrubber (620 ms);
> an unknown `f=` selects nothing rather than erroring; re-adding a
> `src/views` to `src/lessons` import fails `npm run lint` with the INVARIANT
> message.
>
> 3.11 was verified by running tshark over the exact bytes `ExportPcapButton`
> produces — two packets, empty `_ws.expert.severity`. **The Wireshark GUI check
> in 3.11 is still outstanding and is yours to run**: nothing here can open a GUI.

### Phase 3.6 — Lesson UI, unplanned (2026-08-21)

Not in the original plan. Six user-requested additions, built after Phase 3 and
before Phase 3.5, because a lesson that shows a packet but never shows what the
packet *does* was teaching the wire format and nothing else.

| # | What | Where | Verified by |
|---|---|---|---|
| 1 | Ladder labels ride their arrow instead of sitting at a fixed `x` (which was exactly the middle lifeline), with a `paint-order: stroke` halo | `views/FlowView.tsx` | Labels at x=270 for a 3-host segment; no lifeline overlap |
| 2 | Generic, spec-derived packet layout table beside the concrete decode | `core/spec.ts` `specLayout`, `core/registry.ts` `frameLayout`, `views/LayoutView.tsx` | `tests/layout.test.ts` — every row's offset equals the decoded field's `byteStart` |
| 3 | Neighbour cache per host, folded from the decodes as `f(t)` | `core/arp-cache.ts`, `views/ArpCacheView.tsx` | `tests/arp-cache.test.ts` (9 cases), `lesson-page.dom.test.tsx` |
| 4 | Per-host delivery outcome on the ladder: NIC drop, ignored, learned, refreshed, overwritten, answered | `views/FlowView.tsx` | DOM test asserts "NIC drops it" and "entry overwritten" on packet 4 |
| 5 | Field-level diff between the selected packet and its neighbour | `views/PacketDiffView.tsx` | DOM test on the spoof vs the honest reply |
| 6 | Header bands + byte-range legend in the hex view | `views/HexView.tsx` | Existing hex tests still green; legend is non-interactive by design |
| 7 | Second lesson: `#/lesson/arp-spoofing`, four packets | `lessons/arp-spoofing/` | Full tshark differential, plus criterion #7 grep |

**Decisions worth recording:**

- **The cache is core, not UI.** `foldArpCaches` implements RFC 826 packet
  reception — the merge rule, the "only cache if you are the target" rule, and
  the NIC filter — over decoded frames. No host state is read from a scenario.
- **Every host receives every frame on the ladder now.** A shared segment
  delivers to all; what separates broadcast from unicast is what each host
  *does*, which is read out of `eth.dst` rather than from the scenario's `to`.
- **The hex legend is not a control.** Three extra tab stops in front of the
  byte grid would lengthen the keyboard path to the bytes for no new capability;
  the same selection is one click away in the field tree.
- **The spoofing lesson is a separate lesson, not four more packets in the ARP
  one.** It needs its own hosts, its own narration arc and its own capture, and
  the base lesson's two-packet story is what makes the request/reply diff legible.

**A prose claim the oracle refuted.** The spoofing narration originally said
Wireshark opens the capture "without a single expert warning". It does not:
tshark raises `Duplicate IP address configured (10.0.0.2)` at severity
`0x600000` on packet 4, because its ARP dissector keeps its own mapping across
the capture. The narration now says so, and
`tests/tshark-diff.test.ts` pins that exact expert-info row rather than
asserting an empty list. Structural validity is now asserted as "no expert info
reaches error severity" — a claim that survives a dissector with opinions.

**Status: 119 tests green across 15 files, lint clean, build clean.** The
Wireshark GUI check remains outstanding for both captures.

### Phase 3.5 — Live hex editing

Built here, on the simplest protocol, because it is the fastest way to point the
decoder at garbage produced by a human — which feeds straight back into the
Phase 1.6 contract.

| # | Step | Verify |
|---|---|---|
| 3.5.1 | Make `HexView` cells editable (type two hex digits, or ±1 with arrow keys). Edits produce a **new** `Uint8Array`; nothing mutates in place | Edit a byte; React state updates, original scenario buffer unchanged |
| 3.5.2 | Re-run `decode()` on every edit and re-render all four layers from the result | Change ARP opcode byte at offset 21 from `01` to `02` → field tree says Reply, ladder diagram arrow relabels, topology dot direction label flips. No page reload |
| 3.5.3 | Edited packets carry a visible "modified" badge and a Reset button restoring the scenario buffer | Reset → all four layers return to original state |
| 3.5.4 | Export uses the edited bytes; `Problem`s render inline in tree and hex | Set the ARP hardware-length byte to `0xFF` → a `Problem` appears with the offending byte highlighted, no crash. Export, then `tshark -r f.pcap -T fields -e _ws.expert.severity` → tshark also flags it |
| 3.5.5 | `e2e/hex-edit.spec.ts` covers the opcode flip end to end | Playwright test green |

**Why this matters:** it converts the single-source-of-truth invariant from a
README claim into something an interviewer can falsify in five seconds.

### Phase 4 — IPv4, UDP, DHCP codec

| # | Step | Verify |
|---|---|---|
| 4.1 | `src/core/checksum.ts`: RFC 1071 one's-complement sum + UDP pseudo-header variant | `tests/checksum.test.ts`: known RFC 1071 vector; property test — checksum over a buffer with the checksum field inserted sums to `0xFFFF` |
| 4.2 | `src/core/protocols/ipv4.ts`: encode + spec decode, incl. sub-byte version/IHL and flags/frag-offset fields | Decode reports `ipv4.version=4`, `ipv4.ihl=5` with `bitOffset`/`bitLength` set; tshark agrees on `ip.checksum` |
| 4.3 | `src/core/protocols/udp.ts`: encode + decode with pseudo-header checksum | tshark shows `udp.checksum.status: Good` |
| 4.4 | `src/core/protocols/dhcp.ts` fixed header: `op, htype, hlen, hops, xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr[16], sname[64], file[128]`, magic cookie `0x63825363` at offset 236 | Decode finds the cookie at frame-absolute offset `14+20+8+236` |
| 4.5 | DHCP options: TLV encode/decode loop for 53, 54, 51, 50, 55, 1, 3, 6, 255 + padding; each option and each of its sub-parts is a `FieldNode` | `tests/dhcp.test.ts`: option 53 value 1 = DISCOVER; unknown option code decodes as raw bytes, not a crash |
| 4.6 | Extend the round-trip property test to the full DHCP stack | 1000 generated DORA exchanges round-trip |
| 4.7 | Extend the tshark mapping table to IPv4/UDP/DHCP; coverage assertion still holds | `npm test` green; corrupt the UDP checksum → expert-info assertion fails |
| 4.8 | Extend the fuzz test to the full stack. Targeted adversarial cases beyond random bytes: DHCP option with length `0`; option length running past the buffer; IPv4 IHL `< 5` and `> remaining`; UDP length field larger than the frame; option list with no `255` terminator | 5000 fuzz cases plus the named cases → no throw, no hang, each produces a `Problem` with correct byte span. The zero-length-option case specifically must not spin |

### Phase 5 — DHCP lesson

| # | Step | Verify |
|---|---|---|
| 5.1 | `src/lessons/dhcp/scenario.ts`: client `00:11:22:33:44:55`, server `10.0.0.1`, offered `10.0.0.50`, lease 86400s. Four events: Discover (`0.0.0.0:68 → 255.255.255.255:67`, broadcast flag set), Offer, Request (with options 50 + 54), Ack | Page renders 4 packets in the ladder |
| 5.2 | Narration bound to the four timeline marks | Scrubbing advances the narration in step |
| 5.3 | Export + Wireshark check | `tshark -r dhcp.pcap -T fields -e dhcp.option.dhcp` → `1,2,3,5` (DISCOVER/OFFER/REQUEST/ACK) |
| 5.4 | Invariant grep: `grep -nE '\b(86400|0x63825363|53|255\.255\.255\.255)\b' src/lessons/dhcp/scenario.ts` — addresses and lease time are legitimate scene intent; option codes and the magic cookie must **not** appear | Only address/lease literals present |

### Phase 6 — E2E gates

Runs after both lessons exist so the tests iterate real content, not fixtures.

| # | Step | Verify |
|---|---|---|
| 6.1 | Playwright installed; `e2e/smoke.spec.ts` loads home, both lessons, and `#/import` | `npx playwright test` green; CI installs browsers with `npx playwright install --with-deps chromium` |
| 6.2 | `e2e/field-byte-link.spec.ts` — **this replaces manual lesson criterion #4.** For each lesson, for each packet, enumerate every leaf field in the tree; click it; assert the highlighted hex cells are *exactly* `[byteStart, byteStart+byteLength)`. Then the reverse: click a sample of bytes and assert the owning field is selected | Test reports the number of field assertions made (expect ~hundreds across both lessons); deliberately offset one decoder's `byteStart` by 1 → test fails and names the field |
| 6.3 | `scripts/capture-media.ts`: drives Playwright to write `docs/media/*.png` (four layers, a field↔byte click, the concept map) and one `demo.gif` of a hex edit re-decoding | `npm run media` regenerates the files; re-running produces identical PNGs (deterministic: timeline seeked to a fixed `t`, animations disabled) |
| 6.4 | CI runs E2E on every push | Actions log shows the Playwright job green |

### Phase 7 — pcap import

| # | Step | Verify |
|---|---|---|
| 7.1 | `src/core/pcap/read.ts`: parse both endiannesses (`0xa1b2c3d4` / `0xd4c3b2a1`); reject link-types other than 1 with a clear message | `tests/pcap.test.ts`: `read(write(packets))` returns identical buffers; a `LINKTYPE_RAW` file gives a friendly error |
| 7.2 | **Lazy + capped:** on load, walk record headers only (offset + length per packet), decode a packet on selection. Hard cap 5,000 packets with a "showing first 5,000 of N" notice | Generate a 20,000-packet pcap with `tcpdump`/a script → loads in under a second, list shows 5,000 with the notice, memory stays flat until packets are selected |
| 7.3 | `ImportPcapDropzone.tsx` rendered by `ImportPage` at `#/import` → same four-layer viewer, no synthetic timeline (real capture timestamps drive the ladder instead) | Drop the exported `dhcp.pcap` back in → renders identically to `#/lesson/dhcp` |
| 7.4 | Unknown-protocol handling + error boundary: undecodable payload becomes one raw `FieldNode`, still hex-linked; a corrupt file surfaces a message, never a blank page | Import a capture containing TCP → raw payload, no crash. Import `/dev/urandom` truncated to 4 KB and renamed `.pcap` → clear error message, page still interactive |
| 7.5 | Round-trip against a foreign capture | Import a Wireshark-captured ARP/DHCP file from another machine → field values match `tshark -T json` on the same file |

### Phase 8 — Home page concept map, docs, hand-off

Built last on purpose: the map reads the protocol registry, so it needs a
registry with real entries or it would be built twice.

| # | Step | Verify |
|---|---|---|
| 8.1 | `src/core/registry.ts` exposes a describable shape: for each protocol, `{ id, name, layer, encapsulates[], implemented }`. `implemented` is derived from whether a decoder is registered — not a hand-set boolean | Unit test: registry reports `ethernet, arp, ipv4, udp, dhcp` as implemented and nothing else |
| 8.2 | `src/pages/ConceptMap.tsx`: SVG of the encapsulation stack drawn from that registry — nested blocks (Ethernet ⊃ IPv4 ⊃ UDP ⊃ DHCP; Ethernet ⊃ ARP). Implemented blocks are solid and clickable; unimplemented placeholders (TCP, ICMP, DNS) render greyed and inert with a "not implemented" label | Delete the DHCP registry entry locally → DHCP block greys out with no other code change; restore it |
| 8.3 | Wire map interactions: clicking a protocol block filters/highlights the lesson cards that use it; clicking a lesson card navigates to `#/lesson/:slug`. Blocks are keyboard-reachable | Click the ARP block → only the ARP card stays highlighted; click it → lands on the ARP lesson. Same path works by keyboard alone |
| 8.4 | `HeaderDiagram.tsx`: RFC-style 32-bits-per-row box diagram generated from each spec's bit offsets — field name in each box, boxes sized by bit width, rows wrapping at 32 bits. Variable-length regions (DHCP `sname`, `file`, option list) render as a labelled elided block | Ethernet, ARP, IPv4, UDP and the BOOTP fixed header each render a diagram whose box widths sum to the true header size. Add a field to a spec → the diagram changes with no edit to the diagram code |
| 8.5 | `ReferencePage.tsx` at `#/reference` (index of protocols) and `#/reference/:protocol`: header diagram, then a field table (name, offset, size, description, RFC reference), then value dictionaries rendered from `values`, then a **"see it live"** deep link per field into a lesson packet that contains it | Visit `#/reference/dhcp` → every DHCP field listed with a description; clicking "see it live" on `dhcp.opt.53` lands on `#/lesson/dhcp?p=0&f=dhcp.opt.53` with that field selected. Test asserts every spec field appears exactly once on the page |
| 8.6 | Reference is reachable: header nav link on every page, and the field detail panel links to that field's reference row | From a lesson, click the panel's reference link → reference page opens scrolled to that field |
| 8.7 | `HomePage.tsx` final layout: concept map above, lesson card grid below, "Open your own .pcap" card and a "Protocol reference" card in the grid | Home renders map + 2 lesson cards + import card + reference card; no horizontal scroll at 1280px and at 390px |
| 8.8 | `ARCHITECTURE.md` (~1 page): the single-buffer invariant and how it is enforced; spec-driven decoder vs imperative encoder and why not one bidirectional spec; why `tshark` is the oracle; the decoder totality contract; why not Rust/WASM | A reader who has not seen the code can state the invariant and the reason for the codec split |
| 8.9 | README: live link and demo GIF at the top, the correctness proof and how to run it, plus an **"Adding a lesson / adding a protocol"** section written from what actually happened building DHCP | A reader can reproduce the correctness proof and add a third lesson from the README alone |
| 8.10 | CI badge + live Pages link + `docs/media` embedded | Badge green on `main`; GIF renders on the GitHub repo page |

### Phase 9 — Backlog (documented, not committed)

No code. A README section listing candidates so future-you doesn't relearn the
conventions, ordered by value:

1. **TCP handshake** — the first protocol where the ladder diagram earns its
   existence (seq/ack state evolving across packets). Needs flags, options,
   relative-sequence rendering.
2. **DNS query/response** — reuses UDP; name-compression pointers are a genuinely
   interesting decode problem and a good depth story.
3. **ICMP echo** — cheapest (reuses IPv4), but adds the least.
4. **Same-protocol lessons, near-zero core cost** — gratuitous ARP, ARP
   probe/announce, ARP spoofing, DHCP renewal (unicast REQUEST), DHCP NAK.

**Rule:** nothing from this list starts until ARP and DHCP both clear the
definition of done below. Breadth before depth is the specific failure mode this
project exists to avoid.

---

## Definition of done

### For a single lesson

A lesson is done when **all eight** hold:

1. `npm test` is green, including that lesson's tshark differential test and the
   fuzz contract for every protocol it uses.
2. `tshark -r <lesson>.pcap` reports the expected packet count and
   `-e _ws.expert.severity` is empty for every packet.
3. All four layers render, and the timeline plays, pauses, steps and scrubs.
4. `e2e/field-byte-link.spec.ts` passes for this lesson — every leaf field of
   every packet, both directions. **Machine-checked, not eyeballed.**
5. Every packet in the lesson is reachable by a deep link that restores the
   selected field (`#/lesson/<slug>?p=<i>&f=<id>`).
6. The lesson is fully operable by keyboard, and selection remains unambiguous in
   greyscale. Selecting any field fills the detail panel with its explanation —
   no field is unexplained, asserted by test.
7. No protocol field value appears anywhere in `src/lessons/<name>/` — only host
   addresses, timings, lease parameters and prose.
8. `npm run lint` passes, including the `views` ↛ `lessons` restriction.

### For the project (the measurable outcome)

- [ ] Live at `https://icyyolo.github.io/packetViz/`, CI green on `main`.
- [ ] ARP and DHCP lessons both meet all eight lesson criteria.
- [ ] The tshark mapping table covers **100% of leaf field ids** our decoder
      emits for both lessons, asserted by the coverage check — not a sampled
      subset.
- [ ] Both exported `.pcap` files open in the Wireshark GUI with zero malformed
      packets and zero checksum errors.
- [ ] A `.pcap` produced elsewhere (not by this project) containing ARP or DHCP
      can be imported and viewed in the same four-layer viewer.
- [ ] Round-trip property tests pass at 1000+ generated cases for the full
      Ethernet / IPv4 / UDP / DHCP stack.
- [ ] Home page shows the concept map and both lesson cards; every lesson is
      reachable by a shareable deep link (`#/lesson/arp`, `#/lesson/dhcp`), and
      the map's implemented/not-implemented state is derived from the registry —
      proven by the 8.2 delete-and-restore check.
- [ ] README contains an "Adding a lesson / adding a protocol" section accurate
      enough to follow without reading the source, and `ARCHITECTURE.md` states
      the invariant and the codec split.
- [ ] Fuzz test passes 5,000+ cases per protocol with zero throws and zero
      timeouts, and removing any single bounds check makes it fail.
- [ ] Editing a byte in layer 4 re-decodes and updates all four layers live;
      the ARP opcode flip is covered by an E2E test.
- [ ] A 20,000-packet pcap imports without hanging, showing the first 5,000 with
      a clear notice.
- [ ] `#/reference/:protocol` exists for every implemented protocol, is generated
      entirely from the `FieldSpec` tables (adding a field to a spec changes the
      page with no edit to page code), and every field has a description and a
      working "see it live" deep link.

## Known risks

| Risk | Mitigation |
|---|---|
| `tshark` install prompts block CI | `debconf-set-selections` + `DEBIAN_FRONTEND=noninteractive`, pinned in Phase 0.5 |
| tshark JSON field names drift between versions | Mapping table is explicit and version-pinned in CI; a rename fails loudly rather than silently skipping |
| Sub-byte fields (IPv4 version/IHL) don't map cleanly to byte highlighting | Highlight the containing byte, show the bit range in the tree — decided, not deferred |
| Scope drift into "educational website" | The `views` ↛ `lessons` lint rule and lesson criterion #7's grep make drift a build failure |
| Playwright makes CI slow or flaky | Chromium only, animations disabled, timeline seeked to fixed `t` (no waiting on rAF), no arbitrary sleeps |
| Fuzz test finds a hang and blocks progress | Per-case wall-clock timeout means it reports rather than hangs CI; the "advance at least one byte per iteration" rule is a design requirement, not a fix applied later |
| Hex editing lets the user desync a "modified" packet from the lesson narration | Edited packets carry a modified badge; narration is bound to timeline marks, not to field values, so it degrades gracefully rather than lying |
| Feature list keeps growing | Phase 9 is a documented backlog with a hard gate: nothing starts until both lessons clear all eight criteria |
