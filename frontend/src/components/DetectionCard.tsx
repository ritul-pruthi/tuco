import { Link } from 'react-router-dom'
import type { Detection } from '../types/api'

function formatTimestamp(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toISOString().slice(0, 16).replace('T', ' ')
}

function endpoint(ip: string, port: number | null): string {
  return port === null ? ip : `${ip}:${port}`
}

interface DetectionCardProps {
  detection: Detection
}

export function DetectionCard({ detection }: DetectionCardProps) {
  return (
    <article className="detection-card">
      <div className="detection-card-header">
        <span className={`severity-badge severity-${detection.severity}`}>{detection.severity}</span>
        <h2>{detection.title}</h2>
        <Link className="evidence-link" to={`/investigations/${detection.investigation_id}/detections/${detection.id}`}>
          View Evidence ({detection.evidence.length})
        </Link>
      </div>
      <p className="detection-rule mono">{detection.rule_id}</p>
      <p className="detection-endpoints mono">{endpoint(detection.source_ip, detection.source_port)} <span aria-hidden="true">-&gt;</span> {endpoint(detection.destination_ip, detection.destination_port)}</p>
      <p><strong>Observed:</strong> {detection.observed_metric}</p>
      <p className="detection-timeframe"><strong>Timeframe:</strong> <span className="mono">{formatTimestamp(detection.timeframe_start)} -&gt; {formatTimestamp(detection.timeframe_end)}</span></p>
      <p className="detection-explanation">{detection.explanation}</p>
      <p className="detection-limitations">Limitations: {detection.limitations}</p>
    </article>
  )
}

export default DetectionCard
