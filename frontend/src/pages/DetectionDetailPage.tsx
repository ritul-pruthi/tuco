import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { getDetection, getFlow, getHost } from '../services/api'
import type { Detection, Flow, Host } from '../types/api'

interface EvidenceReference {
  type: string
  id: string
  timestamp?: string
}

type LoadedEvidence = { reference: EvidenceReference; flow?: Flow; host?: Host; error?: string }

function formatTimestamp(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toISOString().slice(0, 16).replace('T', ' ')
}

function formatBytes(bytes: number): string {
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function formatEndpoint(ip: string, port: number): string {
  return `${ip}:${port}`
}

function asEvidenceReference(value: Record<string, unknown>): EvidenceReference | null {
  if (typeof value.type !== 'string' || typeof value.id !== 'string') return null
  return { type: value.type, id: value.id, timestamp: typeof value.timestamp === 'string' ? value.timestamp : undefined }
}

export function DetectionDetailPage() {
  const { id = '', detectionId = '' } = useParams<{ id: string; detectionId: string }>()
  const [detection, setDetection] = useState<Detection | null>(null)
  const [evidence, setEvidence] = useState<LoadedEvidence[]>([])
  const [showAllEvidence, setShowAllEvidence] = useState(false)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let isMounted = true
    getDetection(id, detectionId)
      .then(async (loadedDetection) => {
        if (!isMounted) return
        setDetection(loadedDetection)
        const references = loadedDetection.evidence.map(asEvidenceReference).filter((reference): reference is EvidenceReference => reference !== null)
        const loadedEvidence = await Promise.all(references.map(async (reference): Promise<LoadedEvidence> => {
          try {
            if (reference.type === 'flow') return { reference, flow: await getFlow(id, reference.id) }
            if (reference.type === 'host') return { reference, host: await getHost(id, reference.id) }
            return { reference }
          } catch (loadError: unknown) {
            return { reference, error: loadError instanceof Error ? loadError.message : 'Unable to load evidence' }
          }
        }))
        if (isMounted) setEvidence(loadedEvidence)
      })
      .catch((loadError: unknown) => { if (isMounted) setError(loadError instanceof Error ? loadError.message : 'Unable to load detection.') })
      .finally(() => { if (isMounted) setIsLoading(false) })
    return () => { isMounted = false }
  }, [id, detectionId])

  if (isLoading) return <p className="detail-state">Loading detection...</p>
  if (error || !detection) return <section className="detail-state detail-error"><h1>Detection not found</h1><p>{error}</p><Link className="text-link" to={`/investigations/${id}/detections`}>Back to detections</Link></section>

  const visibleEvidence = showAllEvidence ? evidence : evidence.slice(0, 50)
  return (
    <div className="detail-page detection-detail-page">
      <header className="detail-header"><div><p className="eyebrow">Detection detail</p><h1>{detection.title}</h1><p className="detail-subtitle mono">{detection.rule_id}</p></div><span className={`severity-badge severity-${detection.severity}`}>{detection.severity}</span></header>
      <section className="detection-expanded" aria-labelledby="finding-heading">
        <h2 className="sr-only" id="finding-heading">Detection finding</h2>
        <p className="detection-endpoints mono">{detection.source_ip}{detection.source_port === null ? '' : `:${detection.source_port}`} <span aria-hidden="true">-&gt;</span> {detection.destination_ip}{detection.destination_port === null ? '' : `:${detection.destination_port}`}</p>
        <p><strong>Observed:</strong> {detection.observed_metric}</p>
        <p><strong>Timeframe:</strong> <span className="mono">{formatTimestamp(detection.timeframe_start)} -&gt; {formatTimestamp(detection.timeframe_end)}</span></p>
        <p className="detection-explanation">{detection.explanation}</p>
        <p className="detection-limitations">Limitations: {detection.limitations}</p>
      </section>
      <section className="evidence-section" aria-labelledby="evidence-heading">
        <div className="section-heading"><h2 id="evidence-heading">Evidence <span className="record-count">{detection.evidence.length}</span></h2></div>
        {visibleEvidence.length === 0 ? <p className="detail-state">No evidence references were recorded.</p> : <div className="evidence-list">{visibleEvidence.map(({ reference, flow, host, error: evidenceError }) => (
          <article className="evidence-item" key={`${reference.type}-${reference.id}`}>
            <div className="evidence-item-header"><span className="severity-badge evidence-type">{reference.type}</span><span className="mono">{reference.id}</span></div>
            {flow && <p className="mono">{formatEndpoint(flow.src_ip, flow.src_port)} -&gt; {formatEndpoint(flow.dst_ip, flow.dst_port)} · {flow.protocol} · {flow.packets_sent + flow.packets_received} packets · {formatBytes(flow.bytes_sent + flow.bytes_received)}</p>}
            {host && <p className="mono">{host.ip} · {host.scope} · {host.packets_sent + host.packets_received} packets · {formatBytes(host.bytes_sent + host.bytes_received)}</p>}
            {!flow && !host && <p>{reference.timestamp ? formatTimestamp(reference.timestamp) : 'Referenced event'} · Detailed view coming in a later sub-task.</p>}
            {evidenceError && <p className="detection-limitations">{evidenceError}</p>}
            {flow && <Link className="text-link" to={`/investigations/${id}/connections?host=${encodeURIComponent(flow.src_ip)}`}>View connections for {flow.src_ip}</Link>}
            {host && <Link className="text-link" to={`/investigations/${id}/hosts`}>View host</Link>}
          </article>
        ))}</div>}
        {detection.evidence.length > 50 && <button className="evidence-toggle" type="button" aria-expanded={showAllEvidence} onClick={() => setShowAllEvidence((isExpanded) => !isExpanded)}>{showAllEvidence ? `Show first 50` : `Show all ${detection.evidence.length}`}</button>}
      </section>
      <section className="related-section" aria-labelledby="related-heading"><h2 id="related-heading">Related</h2><div className="related-links"><Link to={`/investigations/${id}/connections?host=${encodeURIComponent(detection.source_ip)}`}>All connections for {detection.source_ip}</Link><Link to={`/investigations/${id}/timeline`}>Timeline</Link><Link to={`/investigations/${id}/detections`}>Back to detections</Link></div></section>
    </div>
  )
}

export default DetectionDetailPage
