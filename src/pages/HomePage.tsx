import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { LESSONS } from '../lessons/index.ts'
import { compileScenario } from '../scenario/compile.ts'
import { ConceptMap } from './ConceptMap.tsx'

export function HomePage() {
  const [protocol, setProtocol] = useState<string | null>(null)

  // Packet counts and protocol badges are read out of the decode, not typed
  // into the lesson registry. A lesson cannot advertise a protocol it does not
  // actually put on the wire — which is also what makes the concept map's
  // filter trustworthy.
  const cards = useMemo(
    () =>
      LESSONS.map((lesson) => {
        const timeline = compileScenario(lesson.scenario)
        const protocols = new Set<string>()
        for (const packet of timeline.packets) {
          for (const node of packet.tree) {
            if (node.children !== undefined && node.children.length > 0) {
              protocols.add(node.id)
            }
          }
        }
        return {
          lesson,
          packetCount: timeline.packets.length,
          protocols: Array.from(protocols),
        }
      }),
    [],
  )

  return (
    <div className="home">
      <header className="home-head">
        <h1>PacketViz</h1>
        <p className="home-tagline">
          One packet, four ways to look at it. Every field you see was decoded from a real byte
          buffer built against the wire format — click a field to light up its bytes, click a byte
          to find its field.
        </p>
      </header>

      <ConceptMap selected={protocol} onSelect={setProtocol} />

      <section className="cards" aria-label="Lessons">
        {cards.map(({ lesson, packetCount, protocols }) => {
          const dimmed = protocol !== null && !protocols.includes(protocol)
          return (
            <Link
              className={`card${dimmed ? ' is-dimmed' : ''}`}
              key={lesson.slug}
              to={`/lesson/${lesson.slug}`}
            >
              <h2>{lesson.title}</h2>
              <p>{lesson.blurb}</p>
              <footer className="card-meta">
                <span className="badge-count">
                  {packetCount} packet{packetCount === 1 ? '' : 's'}
                </span>
                {protocols.map((id) => (
                  <span className={`badge${id === protocol ? ' is-selected' : ''}`} key={id}>
                    {id.toUpperCase()}
                  </span>
                ))}
              </footer>
            </Link>
          )
        })}

        <Link className="card card-secondary" to="/import">
          <h2>Open your own .pcap</h2>
          <p>Drop in a capture from Wireshark or tcpdump and read it in the same four layers.</p>
          <footer className="card-meta">
            <span className="badge">pcap</span>
          </footer>
        </Link>

        <Link className="card card-secondary" to="/reference">
          <h2>Protocol reference</h2>
          <p>
            Header diagrams, field tables and value dictionaries — generated from the same spec
            tables the decoder runs, with a link from every field to a packet that contains it.
          </p>
          <footer className="card-meta">
            <span className="badge">RFC</span>
          </footer>
        </Link>
      </section>
    </div>
  )
}
