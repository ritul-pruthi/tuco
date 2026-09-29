import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { getHosts } from '../services/api'
import type { Host } from '../types/api'

function formatBytes(bytes: number): string {
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function formatTimestamp(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toISOString().slice(0, 16).replace('T', ' ')
}

function formatNumber(value: number): string {
  return value.toLocaleString('en-US')
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Unable to load hosts.'
}

export function HostsPage() {
  const { id = '' } = useParams<{ id: string }>()
  const [hosts, setHosts] = useState<Host[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let isMounted = true
    getHosts(id)
      .then((loadedHosts) => {
        if (isMounted) setHosts(loadedHosts)
      })
      .catch((loadError: unknown) => {
        if (isMounted) setError(`Unable to load hosts. ${errorMessage(loadError)}`)
      })
      .finally(() => {
        if (isMounted) setIsLoading(false)
      })
    return () => { isMounted = false }
  }, [id])

  const sortedHosts = [...hosts].sort(
    (left, right) => (right.packets_sent + right.packets_received) - (left.packets_sent + left.packets_received),
  )

  return (
    <div className="detail-page">
      <header className="detail-header">
        <div>
          <p className="eyebrow">Investigation hosts</p>
          <h1>Hosts <span className="record-count">{hosts.length}</span></h1>
          <p className="detail-subtitle">Investigation {id.slice(0, 8)}</p>
        </div>
        <span className="detail-count">Observed endpoints</span>
      </header>
      <section className="detail-content" aria-live="polite">
        {isLoading ? <p className="detail-state">Loading hosts...</p> : error ? <p className="detail-state detail-error" role="alert">{error}</p> : sortedHosts.length === 0 ? <p className="detail-state">No hosts found in this capture.</p> : (
          <div className="table-wrap">
            <table className="data-table">
              <thead><tr><th>IP</th><th>MAC</th><th>Scope</th><th className="numeric">Sent pkts</th><th className="numeric">Recv pkts</th><th className="numeric">Sent bytes</th><th className="numeric">Recv bytes</th><th className="numeric">Unique dsts</th><th className="numeric">Unique ports</th><th>First seen</th></tr></thead>
              <tbody>{sortedHosts.map((host) => <tr key={host.id}>
                <td><Link className="ip-link" to={`/investigations/${id}/connections?host=${encodeURIComponent(host.ip)}`}>{host.ip}</Link></td>
                <td className="mono">{host.mac ?? '—'}</td><td>{host.scope}</td>
                <td className="mono numeric">{formatNumber(host.packets_sent)}</td><td className="mono numeric">{formatNumber(host.packets_received)}</td>
                <td className="mono numeric">{formatBytes(host.bytes_sent)}</td><td className="mono numeric">{formatBytes(host.bytes_received)}</td>
                <td className="mono numeric">{formatNumber(host.unique_destinations)}</td><td className="mono numeric">{formatNumber(host.unique_ports)}</td>
                <td className="mono">{formatTimestamp(host.first_seen)}</td>
              </tr>)}</tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}

export default HostsPage
