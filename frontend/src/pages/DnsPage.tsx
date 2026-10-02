import { useEffect, useMemo, useState } from 'react'
import { useParams, useSearchParams } from 'react-router-dom'
import { getDns } from '../services/api'
import type { DnsRecord } from '../types/api'

function formatTimestamp(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toISOString().slice(0, 19).replace('T', ' ')
}

function formatAnswers(answers: string[]): string {
  return answers.length > 0 ? answers.join(', ') : '—'
}

export function DnsPage() {
  const { id = '' } = useParams<{ id: string }>()
  const [searchParams] = useSearchParams()
  const recordId = searchParams.get('record')
  const [records, setRecords] = useState<DnsRecord[]>([])
  const [search, setSearch] = useState('')
  const [queryType, setQueryType] = useState('all')
  const [responseCode, setResponseCode] = useState('all')
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let isMounted = true
    getDns(id)
      .then((loadedRecords) => { if (isMounted) setRecords(loadedRecords) })
      .catch((loadError: unknown) => { if (isMounted) setError(loadError instanceof Error ? loadError.message : 'Unable to load DNS records.') })
      .finally(() => { if (isMounted) setIsLoading(false) })
    return () => { isMounted = false }
  }, [id])

  const queryTypes = useMemo(() => [...new Set(records.map((record) => record.query_type))].sort(), [records])
  const responseCodes = useMemo(() => [...new Set(records.map((record) => record.response_code))].sort((left, right) => left - right), [records])
  const visibleRecords = records.filter((record) => {
    const searchText = search.trim().toLowerCase()
    const matchesSearch = !searchText || [record.source_ip, record.destination_ip, record.query, record.query_type, ...record.answers]
      .some((value) => value.toLowerCase().includes(searchText))
    return (!recordId || record.id === recordId) && matchesSearch && (queryType === 'all' || record.query_type === queryType) && (responseCode === 'all' || String(record.response_code) === responseCode)
  })

  return (
    <div className="detail-page">
      <header className="detail-header">
        <div><p className="eyebrow">Investigation DNS activity</p><h1>DNS <span className="record-count">{visibleRecords.length}</span></h1><p className="detail-subtitle">Observed DNS activity from this capture.</p></div>
        <span className="detail-count">Investigation {id.slice(0, 8)}</span>
      </header>
      <section className="detail-content" aria-live="polite">
        <div className="dns-filters" aria-label="DNS filters">
          <label>Search <input aria-label="Search DNS records" onChange={(event) => setSearch(event.target.value)} placeholder="Query, address, or answer" value={search} /></label>
          <label>Type <select aria-label="Filter by query type" onChange={(event) => setQueryType(event.target.value)} value={queryType}><option value="all">All types</option>{queryTypes.map((type) => <option key={type} value={type}>{type}</option>)}</select></label>
          <label>Response <select aria-label="Filter by response code" onChange={(event) => setResponseCode(event.target.value)} value={responseCode}><option value="all">All codes</option>{responseCodes.map((code) => <option key={code} value={code}>{code}</option>)}</select></label>
        </div>
        {isLoading ? <p className="detail-state">Loading DNS records...</p> : error ? <p className="detail-state detail-error" role="alert">Unable to load DNS records. {error}</p> : visibleRecords.length === 0 ? <p className="detail-state">No DNS records found in this capture.</p> : (
          <div className="table-wrap"><table className="data-table dns-table">
            <thead><tr><th>Timestamp</th><th>Source</th><th>Destination</th><th>Query</th><th className="type-center">Type</th><th className="response-center">Response</th><th>Answers</th></tr></thead>
            <tbody>{visibleRecords.map((record) => <tr key={record.id}>
              <td className="mono">{formatTimestamp(record.timestamp)}</td><td className="mono">{record.source_ip}</td><td className="mono">{record.destination_ip}</td>
              <td className="mono">{record.query}</td><td className="mono type-center">{record.query_type}</td><td className="mono response-center">{record.response_code}</td><td className="mono">{formatAnswers(record.answers)}</td>
            </tr>)}</tbody>
          </table></div>
        )}
      </section>
    </div>
  )
}

export default DnsPage
