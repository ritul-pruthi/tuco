import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { getDetections, getHosts, getIocs, getInvestigation, getTimeline } from '../services/api'
import type { Detection, Host, Ioc, InvestigationResponse, Severity } from '../types/api'

function formatSize(bytes: number): string {
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function formatTimestamp(value: string | null): string {
  if (!value) return '-'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toISOString().slice(0, 16).replace('T', ' ')
}

function formatDuration(seconds: number | null): string {
  if (seconds === null) return '-'
  return `${seconds.toFixed(1)}s`
}

function formatNumber(value: number): string {
  return value.toLocaleString('en-US')
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Unable to load this data'
}

function isNotFound(error: unknown): boolean {
  return /404|not found/i.test(errorMessage(error))
}

function severitySummary(detections: Detection[]): string {
  const counts = detections.reduce<Partial<Record<Severity, number>>>((summary, detection) => {
    summary[detection.severity] = (summary[detection.severity] ?? 0) + 1
    return summary
  }, {})
  return (['critical', 'high', 'medium', 'low'] as Severity[])
    .filter((severity) => counts[severity])
    .map((severity) => `${counts[severity]} ${severity}`)
    .join(', ')
}

function observableLabel(type: Ioc['ioc_type']): string {
  return type === 'user_agent' ? 'user agent' : type === 'ipv4' ? 'IPv4' : type === 'ipv6' ? 'IPv6' : type === 'url' ? 'URLs' : `${type}s`
}

function observableLink(id: string, ioc: Ioc): string {
  if (ioc.ioc_type === 'ipv4' || ioc.ioc_type === 'ipv6') return `/investigations/${id}/connections?host=${ioc.value}`
  if (ioc.ioc_type === 'domain') return `/investigations/${id}/dns?domain=${ioc.value}`
  if (ioc.ioc_type === 'url') return `/investigations/${id}/http?url=${encodeURIComponent(ioc.value)}`
  return `/investigations/${id}/http?ua=${encodeURIComponent(ioc.value)}`
}

function observableSummary(iocs: Ioc[]): string {
  const counts = iocs.reduce<Record<string, number>>((summary, ioc) => {
    summary[ioc.ioc_type] = (summary[ioc.ioc_type] ?? 0) + 1
    return summary
  }, {})
  return ['ipv4', 'ipv6', 'domain', 'url', 'user_agent']
    .filter((type) => counts[type])
    .map((type) => `${counts[type]} ${observableLabel(type as Ioc['ioc_type'])}`)
    .join(' · ')
}

export function InvestigationOverview() {
  const { id = '' } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [investigation, setInvestigation] = useState<InvestigationResponse | null>(null)
  const [hosts, setHosts] = useState<Host[]>([])
  const [detections, setDetections] = useState<Detection[]>([])
  const [iocs, setIocs] = useState<Ioc[]>([])
  const [timelineCount, setTimelineCount] = useState(0)
  const [errors, setErrors] = useState<string[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [notFound, setNotFound] = useState(false)

  useEffect(() => {
    let isMounted = true
    Promise.allSettled([getInvestigation(id), getHosts(id), getDetections(id), getIocs(id), getTimeline(id)])
      .then(([investigationResult, hostsResult, detectionsResult, iocsResult, timelineResult]) => {
        if (!isMounted) return
        const loadErrors: string[] = []
        if (investigationResult.status === 'fulfilled') {
          setInvestigation(investigationResult.value)
        } else if (isNotFound(investigationResult.reason)) {
          setNotFound(true)
        } else {
          loadErrors.push(`Investigation: ${errorMessage(investigationResult.reason)}`)
        }
        if (hostsResult.status === 'fulfilled') setHosts(hostsResult.value)
        else loadErrors.push(`Hosts: ${errorMessage(hostsResult.reason)}`)
        if (detectionsResult.status === 'fulfilled') setDetections(detectionsResult.value)
        else loadErrors.push(`Detections: ${errorMessage(detectionsResult.reason)}`)
        if (iocsResult.status === 'fulfilled') setIocs(iocsResult.value)
        else loadErrors.push(`Observables: ${errorMessage(iocsResult.reason)}`)
        if (timelineResult.status === 'fulfilled') setTimelineCount(timelineResult.value.length)
        else loadErrors.push(`Timeline: ${errorMessage(timelineResult.reason)}`)
        setErrors(loadErrors)
      })
      .finally(() => {
        if (isMounted) setIsLoading(false)
      })

    return () => {
      isMounted = false
    }
  }, [id])

  if (isLoading) return <p className="overview-state">Loading investigation...</p>
  if (notFound) {
    return (
      <section className="overview-state overview-error">
        <h1>Investigation not found</h1>
        <Link className="text-link" to="/">Return to investigations</Link>
      </section>
    )
  }
  if (!investigation) {
    return <p className="overview-state overview-error" role="alert">{errors[0] ?? 'Unable to load investigation'}</p>
  }

  const sortedHosts = [...hosts].sort(
    (left, right) => (right.packets_sent + right.packets_received) - (left.packets_sent + left.packets_received),
  )
  const visibleHosts = sortedHosts.slice(0, 10)
  const visibleIocs = [...iocs].sort((left, right) => right.occurrences - left.occurrences).slice(0, 5)

  return (
    <div className="overview-page">
      <header className="overview-header">
        <div>
          <p className="eyebrow">Investigation overview</p>
          <h1 className="overview-filename">{investigation.filename}</h1>
          <p className="overview-id">Investigation {investigation.id.slice(0, 8)}</p>
        </div>
        <div className="overview-header-actions">
          <span className={`status status-${investigation.status}`}>{investigation.status}</span>
          <Link className="text-link" to={`/investigations/${id}/timeline`}>View timeline</Link>
          <Link className="text-link" to={`/investigations/${id}/iocs`}>View indicators</Link>
        </div>
      </header>

      {errors.length > 0 && <div className="overview-inline-errors" role="alert">{errors.map((error) => <p key={error}>{error}</p>)}</div>}

      <section aria-labelledby="metadata-heading">
        <h2 className="sr-only" id="metadata-heading">Capture metadata</h2>
        <dl className="metadata-grid">
          <div><dt>Format</dt><dd className="mono">{investigation.format}</dd></div>
          <div><dt>Size</dt><dd className="mono">{formatSize(investigation.size_bytes)}</dd></div>
          <div><dt>Packets</dt><dd className="mono">{investigation.packet_count === null ? '-' : formatNumber(investigation.packet_count)}</dd></div>
          <div><dt>Duration</dt><dd className="mono">{formatDuration(investigation.duration_seconds)}</dd></div>
          <div><dt>First packet</dt><dd className="mono">{formatTimestamp(investigation.started_at)}</dd></div>
          <div><dt>Last packet</dt><dd className="mono">{formatTimestamp(investigation.ended_at)}</dd></div>
          <div><dt>Uploaded</dt><dd className="mono">{formatTimestamp(investigation.created_at)}</dd></div>
        </dl>
        {timelineCount > 0 && <Link className="overview-secondary-link" to={`/investigations/${id}/timeline`}>View full timeline ({timelineCount} events)</Link>}
      </section>

      <div className="overview-sections">
        <section className="overview-section" aria-labelledby="detections-heading">
          <div className="section-heading">
            <h2 id="detections-heading">Detections <span className="record-count">{detections.length}</span></h2>
          </div>
          {detections.length === 0 ? <div className="empty-state"><p>No known patterns matched this capture.</p><p>Absence of detections doesn't mean absence of activity — no detector's threshold was met.</p></div> : (
            <div className="detection-summary">
              <p className="severity-summary">{severitySummary(detections).split(', ').map((part) => {
                const [count, severity] = part.split(' ')
                return <span className={`severity-text severity-${severity}`} key={severity}>{count} {severity}</span>
              }).reduce<React.ReactNode[]>((parts, item, index) => index === 0 ? [item] : [...parts, ', ', item], [])}</p>
              <div className="table-wrap"><table>
                <thead><tr><th>Title</th><th>Severity</th><th>Source</th><th>Destination</th><th>Observed metric</th><th>Evidence</th></tr></thead>
                <tbody>{detections.map((detection) => <tr className="overview-row" key={detection.id} onClick={() => navigate(`/investigations/${id}/detections/${detection.id}`)} tabIndex={0} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') navigate(`/investigations/${id}/detections/${detection.id}`) }}>
                  <td><Link className="text-link" onClick={(event) => event.stopPropagation()} to={`/investigations/${id}/detections/${detection.id}`}>{detection.title}</Link></td><td><span className={`severity-text severity-${detection.severity}`}>{detection.severity}</span></td><td className="mono">{detection.source_ip}</td><td className="mono">{detection.destination_ip}</td><td className="mono numeric">{detection.observed_metric}</td><td><Link className="text-link" onClick={(event) => event.stopPropagation()} to={`/investigations/${id}/detections/${detection.id}`}>View Evidence</Link></td>
                </tr>)}</tbody>
              </table></div>
            </div>
          )}
          <Link className="overview-secondary-link" to={`/investigations/${id}/detections`}>View all detections</Link>
        </section>

        <section className="overview-section" aria-labelledby="hosts-heading">
          <div className="section-heading"><h2 id="hosts-heading">Hosts <span className="record-count">{hosts.length}</span></h2></div>
          {hosts.length === 0 ? <p className="empty-state">No hosts were observed in this capture.</p> : <>
            <div className="table-wrap"><table className="overview-hosts-table">
              <thead><tr><th>IP</th><th>Scope</th><th className="numeric">Sent</th><th className="numeric">Received</th><th>First seen</th><th className="row-details-column">·</th></tr></thead>
              <tbody>{visibleHosts.map((host) => <tr key={host.id}><td className="mono"><Link className="overview-ip-link" to={`/investigations/${id}/connections?host=${host.ip}`}>{host.ip}</Link></td><td>{host.scope}</td><td className="mono numeric">{formatNumber(host.packets_sent)}</td><td className="mono numeric">{formatNumber(host.packets_received)}</td><td className="mono">{formatTimestamp(host.first_seen)}</td><td className="row-details-column"><Link aria-label="View host details" className="row-details-link" to={`/investigations/${id}/hosts?highlight=${encodeURIComponent(host.ip)}`}>›</Link></td></tr>)}</tbody>
            </table></div>
            <Link className="overview-secondary-link" to={`/investigations/${id}/hosts`}>View all {hosts.length} hosts</Link>
            <Link className="overview-secondary-link" to={`/investigations/${id}/connections`}>View all connections</Link>
          </>}
        </section>

        {iocs.length > 0 && <section className="overview-section" aria-labelledby="observables-heading">
          <div className="section-heading"><h2 id="observables-heading">Observables <span className="record-count">{iocs.length}</span></h2></div>
          <p className="observable-summary">{observableSummary(iocs)}</p>
          <div className="table-wrap"><table>
            <thead><tr><th>Type</th><th>Value</th><th className="numeric">Occurrences</th></tr></thead>
            <tbody>{visibleIocs.map((ioc) => <tr key={ioc.id}><td>{observableLabel(ioc.ioc_type)}</td><td className="mono overview-observable-value"><Link className="overview-ip-link" title={ioc.value} to={observableLink(id, ioc)}>{ioc.value.length > 64 ? `${ioc.value.slice(0, 64)}...` : ioc.value}</Link></td><td className="mono numeric">{formatNumber(ioc.occurrences)}</td></tr>)}</tbody>
          </table></div>
          <Link className="overview-secondary-link" to={`/investigations/${id}/iocs`}>View all observables</Link>
        </section>}
      </div>
    </div>
  )
}

export default InvestigationOverview
