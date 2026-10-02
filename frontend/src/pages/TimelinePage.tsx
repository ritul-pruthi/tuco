import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { getTimeline } from '../services/api'
import type { EventType, TimelineEvent } from '../types/api'

type TimelineFilter = 'All' | 'Hosts' | 'DNS' | 'HTTP' | 'TLS' | 'Detections'

const filters: TimelineFilter[] = ['All', 'Hosts', 'DNS', 'HTTP', 'TLS', 'Detections']

function formatTimestamp(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toISOString().slice(0, 19).replace('T', ' ')
}

function shortId(value: string): string {
  return value.slice(0, 8)
}

function eventTypeLabel(eventType: EventType): string {
  return eventType.replaceAll('_', ' ')
}

function matchesFilter(event: TimelineEvent, filter: TimelineFilter): boolean {
  if (filter === 'All') return true
  if (filter === 'Hosts') return event.event_type === 'host_first_seen'
  if (filter === 'DNS') return event.event_type === 'dns_query'
  if (filter === 'HTTP') return event.event_type === 'http_request'
  if (filter === 'TLS') return event.event_type === 'tls_handshake'
  return event.event_type === 'detection' || event.event_type === 'large_transfer'
}

function evidenceLink(id: string, event: TimelineEvent): string | null {
  if (event.evidence_type === 'host') return `/investigations/${id}/hosts`
  if (event.evidence_type === 'flow') return `/investigations/${id}/connections`
  if (event.evidence_type === 'http') return `/investigations/${id}/http`
  if (event.evidence_type === 'detection') return `/investigations/${id}/detections/${event.evidence_id}`
  return null
}

function evidenceLabel(event: TimelineEvent): string {
  if (event.evidence_type === 'host') return 'View host evidence'
  if (event.evidence_type === 'flow') return 'View flow evidence'
  if (event.evidence_type === 'detection') return 'View detection evidence'
  return `${event.evidence_type.toUpperCase()} record ${shortId(event.evidence_id)}`
}

export function TimelinePage() {
  const { id = '' } = useParams<{ id: string }>()
  const [events, setEvents] = useState<TimelineEvent[]>([])
  const [filter, setFilter] = useState<TimelineFilter>('All')
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let isMounted = true
    getTimeline(id)
      .then((loadedEvents) => { if (isMounted) setEvents(loadedEvents) })
      .catch((loadError: unknown) => { if (isMounted) setError(loadError instanceof Error ? loadError.message : 'Unable to load timeline.') })
      .finally(() => { if (isMounted) setIsLoading(false) })
    return () => { isMounted = false }
  }, [id])

  const sortedEvents = [...events].sort((left, right) => Date.parse(left.timestamp) - Date.parse(right.timestamp))
  const visibleEvents = sortedEvents.filter((event) => matchesFilter(event, filter))

  return (
    <div className="detail-page timeline-page">
      <header className="detail-header">
        <div>
          <p className="eyebrow">Investigation activity</p>
          <h1>Timeline <span className="record-count">{events.length}</span></h1>
          <p className="detail-subtitle">Investigation {id.slice(0, 8)}</p>
        </div>
        <span className="detail-count">Chronological evidence</span>
      </header>
      <section className="detail-content" aria-live="polite">
        <div aria-label="Timeline filters" className="timeline-filters" role="group">
          {filters.map((option) => <button className={filter === option ? 'timeline-filter active' : 'timeline-filter'} key={option} onClick={() => setFilter(option)} type="button">{option}</button>)}
        </div>
        {isLoading ? <p className="detail-state">Loading timeline...</p> : error ? <p className="detail-state detail-error" role="alert">Unable to load timeline. {error}</p> : events.length === 0 ? <p className="detail-state">No timeline events for this capture.</p> : (
          <div className="timeline-list">
            {visibleEvents.map((event) => {
              const link = evidenceLink(id, event)
              return <article className="timeline-event" key={event.id}>
                <time className="timeline-timestamp" dateTime={event.timestamp}>{formatTimestamp(event.timestamp)}</time>
                <div className="timeline-content"><span className={`event-badge event-${event.event_type}`}>{eventTypeLabel(event.event_type)}</span><p>{event.summary}</p></div>
                <div className="timeline-evidence">{link ? <Link className="text-link" to={link}>{evidenceLabel(event)}</Link> : <span>{evidenceLabel(event)}</span>}</div>
              </article>
            })}
          </div>
        )}
      </section>
    </div>
  )
}

export default TimelinePage
