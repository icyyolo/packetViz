/**
 * `#/reference` and `#/reference/:protocol` — the wire formats, generated.
 *
 * Not one word of this page is written here. The header diagram, the field
 * table, the descriptions, the RFC citations and the value dictionaries all come
 * from the `FieldSpec` arrays the decoder runs, so a field is explained in
 * exactly one place and adding one changes this page with no edit to this file
 * (`tests/reference.dom.test.tsx` asserts exactly that).
 *
 * The "see it live" links are derived too: every lesson is compiled, and each
 * field is linked to the first packet whose decode actually contains it. A field
 * with no link is a field no lesson exercises — which is information, not a gap
 * to paper over.
 */

import { useEffect, useMemo } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { walkFields } from '../core/field.ts'
import { describeProtocols, findProtocol } from '../core/registry.ts'
import { specLayout, type FieldSpec } from '../core/spec.ts'
import { LESSONS } from '../lessons/index.ts'
import { compileScenario } from '../scenario/compile.ts'
import { HeaderDiagram } from './HeaderDiagram.tsx'

/** Where a field can be seen in real bytes: the first lesson packet that carries it. */
type LiveLink = { slug: string; title: string; packetIndex: number }

function liveLinks(): Map<string, LiveLink> {
  const links = new Map<string, LiveLink>()
  for (const lesson of LESSONS) {
    const timeline = compileScenario(lesson.scenario)
    timeline.packets.forEach((packet, packetIndex) => {
      for (const node of walkFields(packet.tree)) {
        if (!links.has(node.id)) {
          links.set(node.id, { slug: lesson.slug, title: lesson.title, packetIndex })
        }
      }
    })
  }
  return links
}

export function ReferenceIndexPage() {
  const protocols = describeProtocols()

  return (
    <div className="reference">
      <header className="home-head">
        <h1>Protocol reference</h1>
        <p className="home-tagline">
          Header diagrams and field tables for everything PacketViz decodes, generated from the
          same spec tables the decoder runs. Every field links to a packet that contains it.
        </p>
      </header>

      <section className="cards" aria-label="Protocols">
        {protocols.map((protocol) =>
          protocol.implemented ? (
            <Link className="card" key={protocol.id} to={`/reference/${protocol.id}`}>
              <h2>{protocol.name}</h2>
              <p>{protocol.blurb}</p>
              <footer className="card-meta">
                <span className="badge-count">{protocol.specs.length} fields</span>
                <span className="badge">{protocol.reference}</span>
                <span className="badge">L{protocol.layer}</span>
              </footer>
            </Link>
          ) : (
            <div className="card card-secondary is-dimmed" key={protocol.id}>
              <h2>{protocol.name}</h2>
              <p>{protocol.blurb}</p>
              <footer className="card-meta">
                <span className="badge badge-todo">not implemented</span>
                <span className="badge">{protocol.reference}</span>
              </footer>
            </div>
          ),
        )}
      </section>
    </div>
  )
}

export function ReferencePage() {
  const { protocol: id } = useParams<{ protocol: string }>()
  const protocol = findProtocol(id)
  const [searchParams, setSearchParams] = useSearchParams()
  const focused = searchParams.get('f')

  const links = useMemo(() => liveLinks(), [])

  // A link from a lesson's detail panel names a field; land the reader on it
  // rather than at the top of a long table.
  useEffect(() => {
    if (focused === null) return
    document.getElementById(`field-${focused}`)?.scrollIntoView({ block: 'center' })
  }, [focused])

  if (protocol === undefined || !protocol.implemented) {
    return (
      <div className="not-found">
        <h1>No reference for “{id}”</h1>
        <p>
          PacketViz has no decoder for it, so there is no spec table to generate a page from.{' '}
          <Link to="/reference">Back to the reference</Link>.
        </p>
      </div>
    )
  }

  const rows = specLayout(protocol.specs)

  return (
    <div className="reference">
      <header className="home-head">
        <h1>{protocol.name}</h1>
        <p className="home-tagline">{protocol.blurb}</p>
        <p className="reference-meta">
          Layer {protocol.layer} · {protocol.reference} ·{' '}
          {rows.reduce((bits, row) => bits + row.spec.bits, 0) / 8} bytes of fixed header
        </p>
      </header>

      <section aria-label="Header layout">
        <h2>Header layout</h2>
        <HeaderDiagram
          specs={protocol.specs}
          highlighted={focused}
          onSelect={(fieldId) => setSearchParams({ f: fieldId }, { replace: true })}
        />
      </section>

      <section aria-label="Fields">
        <h2>Fields</h2>
        {/* Five columns of prose do not fit a phone; the table scrolls inside
            its own box rather than pushing the page sideways. */}
        <div className="reference-scroll">
        <table className="reference-table">
          <thead>
            <tr>
              <th scope="col">Offset</th>
              <th scope="col">Size</th>
              <th scope="col">Field</th>
              <th scope="col">Meaning</th>
              <th scope="col">See it live</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => {
              const link = links.get(row.spec.id)
              return (
                <tr
                  key={row.spec.id}
                  id={`field-${row.spec.id}`}
                  className={focused === row.spec.id ? 'is-focused' : undefined}
                >
                  <td className="mono">
                    {row.byteStart}
                    {row.spec.bits % 8 === 0 ? '' : `.${row.bitOffset}`}
                  </td>
                  <td className="mono">{sizeOf(row.spec)}</td>
                  <td>
                    <span className="reference-name">{row.spec.name}</span>
                    <code className="reference-id">{row.spec.id}</code>
                  </td>
                  <td>
                    {row.spec.description}
                    {row.spec.reference === undefined ? null : (
                      <span className="reference-rfc"> {row.spec.reference}</span>
                    )}
                    {row.spec.values === undefined ? null : (
                      <ul className="reference-values">
                        {Object.entries(row.spec.values).map(([value, name]) => (
                          <li key={value}>
                            <code>{value}</code> {name}
                          </li>
                        ))}
                      </ul>
                    )}
                  </td>
                  <td>
                    {link === undefined ? (
                      <span className="reference-nolink">no lesson sends this</span>
                    ) : (
                      <Link
                        to={`/lesson/${link.slug}?p=${link.packetIndex}&f=${row.spec.id}`}
                        title={link.title}
                      >
                        packet {link.packetIndex + 1}
                      </Link>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
        </div>
      </section>

      {protocol.dictionaries.map((dictionary) => (
        <section key={dictionary.title} aria-label={dictionary.title}>
          <h2>{dictionary.title}</h2>
          <ul className="reference-dictionary">
            {Object.entries(dictionary.values).map(([value, name]) => (
              <li key={value}>
                <code>{value}</code> {name}
              </li>
            ))}
          </ul>
        </section>
      ))}
    </div>
  )
}

function sizeOf(spec: FieldSpec): string {
  if (spec.bits % 8 !== 0) return `${spec.bits} bits`
  const bytes = spec.bits / 8
  return `${bytes} byte${bytes === 1 ? '' : 's'}`
}
