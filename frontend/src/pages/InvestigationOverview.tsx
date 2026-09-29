import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { getDetections, getHosts, getInvestigation } from '../services/api'
import type { Detection, Host, InvestigationResponse, Severity } from '../types/api'

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

export function InvestigationOverview() {
  const { id = '' } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [investigation, setInvestigation] = useState<InvestigationResponse | null>(null)
  const [hosts, setHosts] = useState<Host[]>([])
  const [detections, setDetections] = useState<Detection[]>([])
  const [errors, setErrors] = useState<string[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [notFound, setNotFound] = useState(false)

  useEffect(() => {
    let isMounted = true
    Promise.allSettled([getInvestigation(id), getHosts(id), getDetections(id)])
      .then(([investigationResult, hostsResult, detectionsResult]) => {
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
      </section>

      <div className="overview-sections">
        <section className="overview-section" aria-labelledby="detections-heading">
          <div className="section-heading">
            <h2 id="detections-heading">Detections <span className="record-count">{detections.length}</span></h2>
          </div>
          {detections.length === 0 ? <p className="empty-state">No detections fired on this capture.</p> : (
            <div className="detection-summary">
              <p className="severity-summary">{severitySummary(detections).split(', ').map((part) => {
                const [count, severity] = part.split(' ')
                return <span className={`severity-text severity-${severity}`} key={severity}>{count} {severity}</span>
              }).reduce<React.ReactNode[]>((parts, item, index) => index === 0 ? [item] : [...parts, ', ', item], [])}</p>
              <div className="table-wrap"><table>
                <thead><tr><th>Title</th><th>Severity</th><th>Source</th><th>Destination</th><th>Observed metric</th><th>Evidence</th></tr></thead>
                <tbody>{detections.map((detection) => <tr className="overview-row" key={detection.id} onClick={() => navigate(`/investigations/${id}/detections`)} tabIndex={0} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') navigate(`/investigations/${id}/detections`) }}>
                  <td>{detection.title}</td><td><span className={`severity-text severity-${detection.severity}`}>{detection.severity}</span></td><td className="mono">{detection.source_ip}</td><td className="mono">{detection.destination_ip}</td><td className="mono numeric">{detection.observed_metric}</td><td><Link className="text-link" onClick={(event) => event.stopPropagation()} to={`/investigations/${id}/detections/${detection.id}`}>View Evidence</Link></td>
                </tr>)}</tbody>
              </table></div>
            </div>
          )}
        </section>

        <section className="overview-section" aria-labelledby="hosts-heading">
          <div className="section-heading"><h2 id="hosts-heading">Hosts <span className="record-count">{hosts.length}</span></h2></div>
          {hosts.length === 0 ? <p className="empty-state">No hosts were observed in this capture.</p> : <>
            <div className="table-wrap"><table>
              <thead><tr><th>IP</th><th>Scope</th><th className="numeric">Sent</th><th className="numeric">Received</th><th>First seen</th></tr></thead>
              <tbody>{visibleHosts.map((host) => <tr key={host.id}><td className="mono">{host.ip}</td><td>{host.scope}</td><td className="mono numeric">{formatNumber(host.packets_sent)}</td><td className="mono numeric">{formatNumber(host.packets_received)}</td><td className="mono">{formatTimestamp(host.first_seen)}</td></tr>)}</tbody>
            </table></div>
            {hosts.length > 10 && <Link className="text-link" to={`/investigations/${id}/hosts`}>Show all {hosts.length} hosts</Link>}
            <Link className="text-link" to={`/investigations/${id}/connections`}>View all connections</Link>
          </>}
        </section>
      </div>
    </div>
  )
}

export default InvestigationOverview
