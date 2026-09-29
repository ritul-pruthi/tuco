import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import DetectionCard from '../components/DetectionCard'
import { getDetections } from '../services/api'
import type { Detection } from '../types/api'

export function DetectionsPage() {
  const { id = '' } = useParams<{ id: string }>()
  const [detections, setDetections] = useState<Detection[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let isMounted = true
    getDetections(id)
      .then((loadedDetections) => { if (isMounted) setDetections(loadedDetections) })
      .catch((loadError: unknown) => { if (isMounted) setError(loadError instanceof Error ? loadError.message : 'Unable to load detections.') })
      .finally(() => { if (isMounted) setIsLoading(false) })
    return () => { isMounted = false }
  }, [id])

  return (
    <div className="detail-page detections-page">
      <header className="detail-header">
        <div><p className="eyebrow">Investigation findings</p><h1>Detections <span className="record-count">{detections.length}</span></h1><p className="detail-subtitle">Investigation {id.slice(0, 8)}</p></div>
        <span className="detail-count">Evidence-backed patterns</span>
      </header>
      <section className="detail-content" aria-live="polite">
        {isLoading ? <p className="detail-state">Loading detections...</p> : error ? <p className="detail-state detail-error" role="alert">Unable to load detections. {error}</p> : detections.length === 0 ? (
          <div className="empty-detections"><h2>No detections fired on this capture.</h2><p>This doesn't mean the capture is benign — it means no known patterns matched.</p></div>
        ) : <div className="detection-list">{detections.map((detection) => <DetectionCard detection={detection} key={detection.id} />)}</div>}
      </section>
    </div>
  )
}

export default DetectionsPage
