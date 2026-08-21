/**
 * The point of the protocol, as a table.
 *
 * One neighbour cache per host, as of the current `t`. Every row is the residue
 * of a frame that arrived: nothing is seeded, nothing is scripted. Scrub back to
 * zero and all three tables are empty, which is the honest starting state and
 * the reason the first packet has to be a broadcast.
 *
 * An entry whose MAC was replaced by a later frame is marked, because that is
 * what a poisoned cache looks like from the victim's side — an ordinary row,
 * indistinguishable from a correct one except for its history.
 */

import type { CacheSnapshot } from '../core/arp-cache.ts'
import { cachesAt } from '../core/arp-cache.ts'
import type { CompiledTimeline } from '../scenario/compile.ts'

export type ArpCacheViewProps = {
  timeline: CompiledTimeline
  snapshots: CacheSnapshot[]
  tMs: number
}

export function ArpCacheView({ timeline, snapshots, tMs }: ArpCacheViewProps) {
  const caches = cachesAt(timeline.hosts, snapshots, tMs)

  return (
    <div className="caches">
      {timeline.hosts.map((host) => {
        const entries = caches.get(host.id) ?? []
        return (
          <section className="cache" key={host.id} aria-label={`${host.label} ARP cache`}>
            <h3>
              {host.label} <span className="cache-addr">{host.ip}</span>
            </h3>
            {entries.length === 0 ? (
              <p className="cache-empty">empty</p>
            ) : (
              <table className="cache-table">
                <thead>
                  <tr>
                    <th scope="col">IP address</th>
                    <th scope="col">MAC address</th>
                    <th scope="col">Learned</th>
                  </tr>
                </thead>
                <tbody>
                  {entries.map((entry) => (
                    <tr key={entry.ip} className={entry.overwritten ? 'is-overwritten' : ''}>
                      <td>{entry.ip}</td>
                      <td>{entry.mac}</td>
                      <td>
                        #{entry.learnedFrom + 1} at {entry.learnedMs} ms
                        {entry.overwritten ? <span className="cache-flag">overwritten</span> : null}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
        )
      })}
    </div>
  )
}
