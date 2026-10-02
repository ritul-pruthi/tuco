import { useEffect, useMemo, useState } from 'react'
import { useParams } from 'react-router-dom'
import { getHttp } from '../services/api'
import type { HttpRecord } from '../types/api'

function formatTimestamp(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toISOString().slice(0, 19).replace('T', ' ')
}

function displayValue(value: string | null, fallback = '—'): string {
  return value ?? fallback
}

export function HttpPage() {
  const { id = '' } = useParams<{ id: string }>()
  const [records, setRecords] = useState<HttpRecord[]>([])
  const [search, setSearch] = useState('')
  const [method, setMethod] = useState('all')
  const [statusCode, setStatusCode] = useState('all')
  const [host, setHost] = useState('all')
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let isMounted = true
    getHttp(id)
      .then((loadedRecords) => { if (isMounted) setRecords(loadedRecords) })
      .catch((loadError: unknown) => { if (isMounted) setError(loadError instanceof Error ? loadError.message : 'Unable to load HTTP records.') })
      .finally(() => { if (isMounted) setIsLoading(false) })
    return () => { isMounted = false }
  }, [id])

  const methods = useMemo(() => [...new Set(records.map((record) => record.method))].sort(), [records])
  const statusCodes = useMemo(() => [...new Set(records.flatMap((record) => record.status_code === null ? [] : [record.status_code]))].sort((left, right) => left - right), [records])
  const hosts = useMemo(() => [...new Set(records.flatMap((record) => record.host === null ? [] : [record.host]))].sort(), [records])
  const visibleRecords = records.filter((record) => {
    const searchText = search.trim().toLowerCase()
    const matchesSearch = !searchText || [record.source_ip, record.destination_ip, record.method, record.host, record.path, record.user_agent]
      .filter((value): value is string => value !== null)
      .some((value) => value.toLowerCase().includes(searchText))
    return matchesSearch && (method === 'all' || record.method === method) && (statusCode === 'all' || String(record.status_code) === statusCode) && (host === 'all' || record.host === host)
  })

  return (
    <div className="detail-page">
      <header className="detail-header">
        <div><p className="eyebrow">Investigation HTTP activity</p><h1>HTTP <span className="record-count">{visibleRecords.length}</span></h1><p className="detail-subtitle">HTTP evidence observed in this capture.</p></div>
        <span className="detail-count">Investigation {id.slice(0, 8)}</span>
      </header>
      <section className="detail-content" aria-live="polite">
        <div className="dns-filters" aria-label="HTTP filters">
          <label>Search <input aria-label="Search HTTP records" onChange={(event) => setSearch(event.target.value)} placeholder="Host, path, address, or method" value={search} /></label>
          <label>Method <select aria-label="Filter by HTTP method" onChange={(event) => setMethod(event.target.value)} value={method}><option value="all">All methods</option>{methods.map((value) => <option key={value} value={value}>{value}</option>)}</select></label>
          <label>Status <select aria-label="Filter by status code" onChange={(event) => setStatusCode(event.target.value)} value={statusCode}><option value="all">All codes</option>{statusCodes.map((value) => <option key={value} value={value}>{value}</option>)}</select></label>
          <label>Host <select aria-label="Filter by HTTP host" onChange={(event) => setHost(event.target.value)} value={host}><option value="all">All hosts</option>{hosts.map((value) => <option key={value} value={value}>{value}</option>)}</select></label>
        </div>
        {isLoading ? <p className="detail-state">Loading HTTP records...</p> : error ? <p className="detail-state detail-error" role="alert">Unable to load HTTP records. {error}</p> : visibleRecords.length === 0 ? <p className="detail-state">No HTTP records found in this capture.</p> : (
          <div className="table-wrap"><table className="data-table http-table">
            <thead><tr><th>Timestamp</th><th>Source</th><th>Destination</th><th className="method-center">Method</th><th className="host-center">Host</th><th className="path-center">Path</th><th>Status</th><th>User Agent</th></tr></thead>
            <tbody>{visibleRecords.map((record) => <tr key={record.id}>
              <td className="mono">{formatTimestamp(record.timestamp)}</td><td className="mono">{record.source_ip}:{record.source_port}</td><td className="mono">{record.destination_ip}:{record.destination_port}</td>
              <td className="mono method-center">{record.method}</td><td className="mono truncate host-center" title={displayValue(record.host)}>{displayValue(record.host)}</td><td className="mono truncate path-center" title={displayValue(record.path)}>{displayValue(record.path)}</td>
              <td className="mono numeric">{record.status_code ?? '—'}</td><td className="mono truncate" title={displayValue(record.user_agent)}>{displayValue(record.user_agent)}</td>
            </tr>)}</tbody>
          </table></div>
        )}
      </section>
    </div>
  )
}

export default HttpPage
