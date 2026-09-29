import '@testing-library/jest-dom/vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import TimelinePage from '../src/pages/TimelinePage'

const events = [
  { id: 'event-2', investigation_id: 'abc12345', timestamp: '2026-09-30T10:01:00Z', event_type: 'dns_query', source: '10.0.0.5', destination: '8.8.8.8', summary: 'DNS query for example.com', evidence_type: 'dns', evidence_id: 'dns-12345678' },
  { id: 'event-1', investigation_id: 'abc12345', timestamp: '2026-09-30T10:00:00Z', event_type: 'host_first_seen', source: '10.0.0.5', destination: null, summary: 'Host first seen', evidence_type: 'host', evidence_id: 'host-1' },
  { id: 'event-3', investigation_id: 'abc12345', timestamp: '2026-09-30T10:02:00Z', event_type: 'detection', source: '10.0.0.5', destination: '10.0.0.15', summary: 'Internal reconnaissance detected', evidence_type: 'detection', evidence_id: 'det-42' },
]

function renderPage() {
  return render(<MemoryRouter initialEntries={['/investigations/abc12345/timeline']}><Routes><Route path="/investigations/:id/timeline" element={<TimelinePage />} /></Routes></MemoryRouter>)
}

afterEach(() => vi.restoreAllMocks())

describe('TimelinePage', () => {
  it('renders events sorted ascending', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => events }))
    renderPage()
    const rows = await screen.findAllByRole('article')
    expect(rows[0]).toHaveTextContent('2026-09-30 10:00:00')
    expect(rows[1]).toHaveTextContent('2026-09-30 10:01:00')
  })

  it('renders event badges with their event type text', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => events }))
    renderPage()
    expect(await screen.findByText('host first seen')).toBeInTheDocument()
    expect(screen.getByText('dns query')).toBeInTheDocument()
    expect(screen.getByText('detection')).toBeInTheDocument()
  })

  it('filters to DNS events', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => events }))
    renderPage()
    await screen.findByText('Internal reconnaissance detected')
    fireEvent.click(screen.getByRole('button', { name: 'DNS' }))
    await waitFor(() => expect(screen.getAllByRole('article')).toHaveLength(1))
    expect(screen.getByText('DNS query for example.com')).toBeInTheDocument()
  })

  it('renders the empty state', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => [] }))
    renderPage()
    expect(await screen.findByText('No timeline events for this capture.')).toBeInTheDocument()
  })

  it('links detection evidence to the detection detail', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => events }))
    renderPage()
    await screen.findByText('Internal reconnaissance detected')
    expect(screen.getByRole('link', { name: 'View detection evidence' })).toHaveAttribute('href', '/investigations/abc12345/detections/det-42')
  })
})
