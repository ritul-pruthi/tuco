import '@testing-library/jest-dom/vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import InvestigationOverview from '../src/pages/InvestigationOverview'

const investigation = {
  id: 'abcdef1234567890', filename: 'http.pcap', format: 'pcap', size_bytes: 2048,
  packet_count: 1234, started_at: '2026-09-30T10:00:00Z', ended_at: '2026-09-30T10:00:30Z',
  duration_seconds: 30.4, status: 'aggregated', created_at: '2026-09-30T10:02:00Z',
}
const host = { id: 'host-1', investigation_id: investigation.id, ip: '10.0.0.1', mac: null, scope: 'internal', packets_sent: 10, packets_received: 20, bytes_sent: 100, bytes_received: 200, unique_destinations: 1, unique_ports: 2, first_seen: '2026-09-30T10:00:01Z', last_seen: '2026-09-30T10:00:20Z' }
const detection = { id: 'det-1', investigation_id: investigation.id, rule_id: 'port_scan', title: 'Port scan', severity: 'medium', confidence: 'high', source_ip: '10.0.0.1', source_port: null, destination_ip: '10.0.0.2', destination_port: 22, timeframe_start: investigation.started_at, timeframe_end: investigation.ended_at, observed_metric: 'unique_ports', observed_value: 12, threshold_description: '12 ports', threshold_value: 5, explanation: 'Observed port activity', evidence: [], limitations: 'Heuristic', created_at: investigation.created_at }

function renderPage() {
  return render(<MemoryRouter initialEntries={[`/investigations/${investigation.id}`]}><Routes><Route path="/investigations/:id" element={<InvestigationOverview />} /></Routes></MemoryRouter>)
}

function mockFetch(data: { investigation?: unknown; hosts?: unknown; detections?: unknown; investigationError?: boolean }) {
  vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string) => {
    if (url.endsWith(`/${investigation.id}`)) return Promise.resolve(data.investigationError ? { ok: false, status: 404, json: async () => ({ detail: 'Investigation not found' }) } : { ok: true, json: async () => data.investigation ?? investigation })
    if (url.endsWith('/hosts')) return Promise.resolve({ ok: true, json: async () => data.hosts ?? [host] })
    return Promise.resolve({ ok: true, json: async () => data.detections ?? [detection] })
  }))
}

afterEach(() => vi.restoreAllMocks())

describe('InvestigationOverview', () => {
  it('renders metadata, severity summary, and hosts', async () => {
    mockFetch({})
    renderPage()
    expect(await screen.findByText('http.pcap')).toBeInTheDocument()
    expect(screen.getByText('1,234')).toBeInTheDocument()
    expect(screen.getByText('1 medium')).toBeInTheDocument()
    expect(screen.getAllByText('10.0.0.1')).not.toHaveLength(0)
  })

  it('renders the not found state', async () => {
    mockFetch({ investigationError: true })
    renderPage()
    expect(await screen.findByText('Investigation not found')).toBeInTheDocument()
  })

  it('renders the empty detections state', async () => {
    mockFetch({ detections: [] })
    renderPage()
    expect(await screen.findByText('No detections fired on this capture.')).toBeInTheDocument()
  })
})
