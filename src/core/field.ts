/**
 * The decode output types. Every offset here is ABSOLUTE within the frame,
 * which is what makes the field-tree <-> hex-dump link trivial: a node's
 * `[byteStart, byteStart + byteLength)` is directly a range of hex cells.
 */

export type FieldNode = {
  /** Stable dotted path, e.g. "eth.dst", "arp.opcode". */
  id: string
  name: string
  /** Absolute offset within the frame. */
  byteStart: number
  byteLength: number
  /** Set only for sub-byte fields; the node still highlights whole bytes. */
  bitOffset?: number
  bitLength?: number
  /** A view into the frame, never a copy. */
  raw: Uint8Array
  /** Human-rendered value. */
  value: string
  /** Teaching text. Not a protocol fact — it comes from the FieldSpec table. */
  description?: string
  /** e.g. "RFC 826 §2". */
  reference?: string
  children?: FieldNode[]
}

export type Problem = {
  severity: 'error' | 'warning'
  message: string
  /** Problems carry a byte span so they highlight in hex like any field. */
  byteStart: number
  byteLength: number
}

export type DecodedPacket = {
  frame: Uint8Array
  /** Top level is one node per protocol layer: Ethernet, then its payload. */
  tree: FieldNode[]
  summary: string
  problems: Problem[]
}

/** What one protocol decoder contributes to a packet. */
export type DecodeResult = {
  nodes: FieldNode[]
  problems: Problem[]
  summary: string
  /** Bytes consumed from the offset the decoder was called at. */
  byteLength: number
}

/** Depth-first walk over every node in a tree, containers included. */
export function* walkFields(nodes: readonly FieldNode[]): Generator<FieldNode> {
  for (const node of nodes) {
    yield node
    if (node.children) yield* walkFields(node.children)
  }
}

/** Depth-first walk over leaf nodes only — the ones that own byte ranges. */
export function* leafFields(nodes: readonly FieldNode[]): Generator<FieldNode> {
  for (const node of nodes) {
    if (node.children && node.children.length > 0) yield* leafFields(node.children)
    else yield node
  }
}

export function findField(nodes: readonly FieldNode[], id: string): FieldNode | undefined {
  for (const node of walkFields(nodes)) {
    if (node.id === id) return node
  }
  return undefined
}
