import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { getIocs } from '../services/api'
import type { Ioc, IocType } from '../types/api'

const iocSections: { type: IocType; label: string }[] = [
  { type: 'ipv4', label: 'IPv4 addresses' },
  { type: 'ipv6', label: 'IPv6 addresses' },
  { type: 'domain', label: 'Domains' },
  { type: 'url', label: 'URLs' },
  { type: 'user_agent', label: 'User agents' },
]

function formatTimestamp(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toISOString().slice(0, 16).replace('T', ' ')
}

function formatNumber(value: number): string {
  return value.toLocaleString('en-US')
}

function evidenceLink(id: string, ioc: Ioc): string | null {
  if (ioc.evidence_type === 'host') return `/investigations/${id}/hosts`
  if (ioc.evidence_type === 'flow') return `/investigations/${id}/connections`
  return null
}

function evidenceLabel(ioc: Ioc): string {
  if (ioc.evidence_type === 'host') return 'Host records'
  if (ioc.evidence_type === 'flow') return 'Flow records'
  if (ioc.evidence_type === 'dns') return 'DNS record'
  if (ioc.evidence_type === 'http') return 'HTTP record'
  return 'mixed sources'
}

function scopeClass(scope: string): string {
  return `ioc-scope ioc-scope-${scope}`
}

function IocTable({ id, iocs, type }: { id: string; iocs: Ioc[]; type: IocType }) {
  const showScope = type === 'ipv4' || type === 'ipv6'
  const showLastSeen = type !== 'url' && type !== 'user_agent'
  return (
    <div className="table-wrap">
      <table className="data-table ioc-table">
        <thead><tr>
          <th>Value</th>
          {showScope && <th>Scope</th>}
          <th className="numeric">Occurrences</th>
          <th>First seen</th>
          {showLastSeen && <th>Last seen</th>}
          <th>Evidence</th>
        </tr></thead>
        <tbody>{iocs.map((ioc) => {
          const link = evidenceLink(id, ioc)
          const value = type === 'url' ? ioc.value.slice(0, 80) : ioc.value
          return <tr key={ioc.id}>
            <td className={type === 'user_agent' ? 'ioc-user-agent' : 'mono'} title={type === 'url' ? ioc.value : undefined}>{value}{type === 'url' && ioc.value.length > 80 ? '...' : ''}</td>
            {showScope && <td><span className={scopeClass(ioc.scope)}>{ioc.scope}</span></td>}
            <td className="mono numeric">{formatNumber(ioc.occurrences)}</td>
            <td className="mono">{formatTimestamp(ioc.first_seen)}</td>
            {showLastSeen && <td className="mono">{formatTimestamp(ioc.last_seen)}</td>}
            <td>{link ? <Link className="text-link" to={link}>{evidenceLabel(ioc)}</Link> : <span className="ioc-muted-evidence">{evidenceLabel(ioc)}</span>}</td>
          </tr>
        })}</tbody>
      </table>
    </div>
  )
}

export function IocsPage() {
  const { id = '' } = useParams<{ id: string }>()
  const [iocs, setIocs] = useState<Ioc[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let isMounted = true
    getIocs(id)
      .then((loadedIocs) => { if (isMounted) setIocs(loadedIocs) })
      .catch((loadError: unknown) => { if (isMounted) setError(loadError instanceof Error ? loadError.message : 'Unable to load indicators.') })
      .finally(() => { if (isMounted) setIsLoading(false) })
    return () => { isMounted = false }
  }, [id])

  return <div className="detail-page iocs-page">
    <header className="detail-header">
      <div>
        <p className="eyebrow">Investigation indicators</p>
        <h1>Indicators of Compromise <span className="record-count">{iocs.length}</span></h1>
        <p className="detail-subtitle">Observed indicators from this capture. These are observations, not verdicts.</p>
      </div>
      <span className="detail-count">Investigation {id.slice(0, 8)}</span>
    </header>
    <section className="detail-content" aria-live="polite">
      {isLoading ? <p className="detail-state">Loading indicators...</p> : error ? <p className="detail-state detail-error" role="alert">Unable to load indicators. {error}</p> : iocs.length === 0 ? <p className="detail-state">No indicators extracted from this capture.</p> : (
        <div className="ioc-sections">
          {iocSections.map(({ type, label }) => {
            const sectionIocs = iocs.filter((ioc) => ioc.ioc_type === type)
            if (sectionIocs.length === 0) return null
            return <section aria-labelledby={`${type}-heading`} className="ioc-section" key={type}>
              <h2 className="ioc-section-heading" id={`${type}-heading`}>{label} <span className="record-count">{sectionIocs.length}</span></h2>
              <IocTable id={id} iocs={sectionIocs} type={type} />
            </section>
          })}
        </div>
      )}
    </section>
  </div>
}

export default IocsPage
