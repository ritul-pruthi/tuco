import { useEffect, useMemo, useState } from 'react'
import { useParams, useSearchParams } from 'react-router-dom'
import { getTls } from '../services/api'
import type { TlsRecord } from '../types/api'

function formatTimestamp(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toISOString().slice(0, 19).replace('T', ' ')
}

function displayValue(value: string | null | undefined, fallback = '—'): string {
  return value ?? fallback
}

export function TlsPage() {
  const { id = '' } = useParams<{ id: string }>()
  const [searchParams] = useSearchParams()
  const recordId = searchParams.get('record')
  const [records, setRecords] = useState<TlsRecord[]>([])
  const [search, setSearch] = useState('')
  const [version, setVersion] = useState('all')
  const [sni, setSni] = useState('all')
  const [destination, setDestination] = useState('all')
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let isMounted = true
    getTls(id)
      .then((loadedRecords) => { if (isMounted) setRecords(loadedRecords) })
      .catch((loadError: unknown) => { if (isMounted) setError(loadError instanceof Error ? loadError.message : 'Unable to load TLS records.') })
      .finally(() => { if (isMounted) setIsLoading(false) })
    return () => { isMounted = false }
  }, [id])

  const versions = useMemo(() => [...new Set(records.flatMap((record) => record.tls_version ? [record.tls_version] : []))].sort(), [records])
  const sniValues = useMemo(() => [...new Set(records.flatMap((record) => record.sni ? [record.sni] : []))].sort(), [records])
  const destinations = useMemo(() => [...new Set(records.map((record) => record.destination_ip))].sort(), [records])

  const visibleRecords = records.filter((record) => {
    const searchText = search.trim().toLowerCase()
    const matchesSearch = !searchText || [
      record.source_ip,
      record.destination_ip,
      String(record.source_port),
      String(record.destination_port),
      record.sni,
      record.tls_version,
      record.certificate_subject,
      record.certificate_issuer,
    ].filter((value): value is string => value !== null && value !== undefined).some((value) => value.toLowerCase().includes(searchText))
    return (!recordId || record.id === recordId) && matchesSearch && (version === 'all' || record.tls_version === version) && (sni === 'all' || record.sni === sni) && (destination === 'all' || record.destination_ip === destination)
  })

  return (
    <div className="detail-page">
      <header className="detail-header">
        <div>
          <p className="eyebrow">Investigation TLS activity</p>
          <h1>TLS <span className="record-count">{visibleRecords.length}</span></h1>
          <p className="detail-subtitle">TLS metadata observed in this capture.</p>
        </div>
        <span className="detail-count">Investigation {id.slice(0, 8)}</span>
      </header>

      <section className="detail-content" aria-live="polite">
        <div className="dns-filters" aria-label="TLS filters">
          <label>Search <input aria-label="Search TLS records" onChange={(event) => setSearch(event.target.value)} placeholder="IP, SNI, or certificate" value={search} /></label>
          <label>Version <select aria-label="Filter by TLS version" onChange={(event) => setVersion(event.target.value)} value={version}><option value="all">All versions</option>{versions.map((value) => <option key={value} value={value}>{value}</option>)}</select></label>
          <label>SNI <select aria-label="Filter by SNI" onChange={(event) => setSni(event.target.value)} value={sni}><option value="all">All SNI values</option>{sniValues.map((value) => <option key={value} value={value}>{value}</option>)}</select></label>
          <label>Destination <select aria-label="Filter by destination" onChange={(event) => setDestination(event.target.value)} value={destination}><option value="all">All destinations</option>{destinations.map((value) => <option key={value} value={value}>{value}</option>)}</select></label>
        </div>

        {isLoading ? <p className="detail-state">Loading TLS records...</p> : error ? <p className="detail-state detail-error" role="alert">Unable to load TLS records. {error}</p> : visibleRecords.length === 0 ? <p className="detail-state">No TLS records found in this capture.</p> : (
          <div className="table-wrap">
            <table className="data-table tls-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th className="tls-port-column">Port</th>
                  <th>TLS Version</th>
                  <th>SNI</th>
                  <th className="tls-certificate-column">Certificate</th>
                  <th className="tls-issuer-column">Issuer</th>
                </tr>
              </thead>
              <tbody>
                {visibleRecords.map((record) => (
                  <tr key={record.id}>
                    <td className="mono">{formatTimestamp(record.timestamp)}</td>
                    <td className="mono">{record.source_ip}:{record.source_port}</td>
                    <td className="mono">{record.destination_ip}:{record.destination_port}</td>
                    <td className="mono tls-port-column">{record.destination_port}</td>
                    <td className="mono">{displayValue(record.tls_version)}</td>
                    <td className="mono truncate" title={displayValue(record.sni)}>{displayValue(record.sni)}</td>
                    <td className="mono truncate tls-certificate-column" title={displayValue(record.certificate_subject)}>{displayValue(record.certificate_subject)}</td>
                    <td className="mono truncate tls-issuer-column" title={displayValue(record.certificate_issuer)}>{displayValue(record.certificate_issuer)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}

export default TlsPage
