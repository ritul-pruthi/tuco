import { useEffect, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { getFlows } from '../services/api'
import type { Flow } from '../types/api'

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

function protocolClass(protocol: string): string {
  return `protocol-${protocol.toLowerCase()}`
}

export function FlowsPage() {
  const { id = '' } = useParams<{ id: string }>()
  const [searchParams] = useSearchParams()
  const hostFilter = searchParams.get('host')
  const [flows, setFlows] = useState<Flow[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let isMounted = true
    getFlows(id)
      .then((loadedFlows) => { if (isMounted) setFlows(loadedFlows) })
      .catch((loadError: unknown) => { if (isMounted) setError(loadError instanceof Error ? `Unable to load connections. ${loadError.message}` : 'Unable to load connections.') })
      .finally(() => { if (isMounted) setIsLoading(false) })
    return () => { isMounted = false }
  }, [id])

  const visibleFlows = flows
    .filter((flow) => !hostFilter || flow.src_ip === hostFilter || flow.dst_ip === hostFilter)
    .sort((left, right) => (right.bytes_sent + right.bytes_received) - (left.bytes_sent + left.bytes_received))

  return (
    <div className="detail-page">
      <header className="detail-header">
        <div><p className="eyebrow">Investigation network</p><h1>Connections <span className="record-count">{visibleFlows.length}</span></h1><p className="detail-subtitle">Investigation {id.slice(0, 8)}</p></div>
        <span className="detail-count">Observed flows</span>
      </header>
      <section className="detail-content" aria-live="polite">
        {hostFilter && <div className="filter-bar"><span>Filtered by host <span className="mono">{hostFilter}</span></span><Link className="text-link" to={`/investigations/${id}/connections`}>Clear filter</Link></div>}
        {isLoading ? <p className="detail-state">Loading connections...</p> : error ? <p className="detail-state detail-error" role="alert">{error}</p> : visibleFlows.length === 0 ? <p className="detail-state">No connections found.</p> : (
          <div className="table-wrap"><table className="data-table">
            <thead><tr><th>Source</th><th>Destination</th><th>Protocol</th><th>State</th><th className="numeric">Sent pkts</th><th className="numeric">Recv pkts</th><th className="numeric">Sent bytes</th><th className="numeric">Recv bytes</th><th>First seen</th><th>Last seen</th></tr></thead>
            <tbody>{visibleFlows.map((flow) => <tr key={flow.id}>
              <td className="mono">{flow.src_ip}:{flow.src_port}</td><td className="mono">{flow.dst_ip}:{flow.dst_port}</td>
              <td className={`mono ${protocolClass(flow.protocol)}`}>{flow.protocol}</td><td className="mono">{flow.tcp_state ?? '—'}</td>
              <td className="mono numeric">{formatNumber(flow.packets_sent)}</td><td className="mono numeric">{formatNumber(flow.packets_received)}</td>
              <td className="mono numeric">{formatBytes(flow.bytes_sent)}</td><td className="mono numeric">{formatBytes(flow.bytes_received)}</td>
              <td className="mono">{formatTimestamp(flow.first_seen)}</td><td className="mono">{formatTimestamp(flow.last_seen)}</td>
            </tr>)}</tbody>
          </table></div>
        )}
      </section>
    </div>
  )
}

export default FlowsPage
