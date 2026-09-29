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
const ioc = { id: 'ioc-1', investigation_id: investigation.id, ioc_type: 'ipv4', value: '10.0.0.2', first_seen: investigation.started_at, last_seen: investigation.ended_at, occurrences: 4, scope: 'internal', evidence_type: 'host', evidence_ids: ['host-1'] }

function renderPage() {
  return render(<MemoryRouter initialEntries={[`/investigations/${investigation.id}`]}><Routes><Route path="/investigations/:id" element={<InvestigationOverview />} /></Routes></MemoryRouter>)
}

function mockFetch(data: { investigation?: unknown; hosts?: unknown; detections?: unknown; iocs?: unknown; timeline?: unknown; investigationError?: boolean }) {
  vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string) => {
    if (url.endsWith(`/${investigation.id}`)) return Promise.resolve(data.investigationError ? { ok: false, status: 404, json: async () => ({ detail: 'Investigation not found' }) } : { ok: true, json: async () => data.investigation ?? investigation })
    if (url.endsWith('/hosts')) return Promise.resolve({ ok: true, json: async () => data.hosts ?? [host] })
    if (url.endsWith('/detections')) return Promise.resolve({ ok: true, json: async () => data.detections ?? [detection] })
    if (url.endsWith('/iocs')) return Promise.resolve({ ok: true, json: async () => data.iocs ?? [ioc] })
    return Promise.resolve({ ok: true, json: async () => data.timeline ?? [] })
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
    expect(screen.getByRole('link', { name: '10.0.0.1' })).toHaveAttribute('href', `/investigations/${investigation.id}/connections?host=10.0.0.1`)
    expect(screen.getByRole('link', { name: 'View host details' })).toHaveAttribute('href', `/investigations/${investigation.id}/hosts?highlight=${encodeURIComponent(host.ip)}`)
    expect(screen.getByRole('link', { name: 'View all 1 hosts' })).toHaveAttribute('href', `/investigations/${investigation.id}/hosts`)
  })

  it('renders the not found state', async () => {
    mockFetch({ investigationError: true })
    renderPage()
    expect(await screen.findByText('Investigation not found')).toBeInTheDocument()
  })

  it('renders the empty detections state', async () => {
    mockFetch({ detections: [] })
    renderPage()
    expect(await screen.findByText('Detections')).toBeInTheDocument()
    expect(screen.getByText('No known patterns matched this capture.')).toBeInTheDocument()
    expect(screen.getByText("Absence of detections doesn't mean absence of activity — no detector's threshold was met.")).toBeInTheDocument()
  })

  it('renders observables and their pivots when IOCs exist', async () => {
    mockFetch({ iocs: [ioc] })
    renderPage()
    expect(await screen.findByText('Observables')).toBeInTheDocument()
    expect(screen.getByText('1 IPv4')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: ioc.value })).toHaveAttribute('href', `/investigations/${investigation.id}/connections?host=${ioc.value}`)
  })

  it('hides observables when IOCs are empty', async () => {
    mockFetch({ iocs: [] })
    renderPage()
    expect(await screen.findByText('http.pcap')).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: /Observables/ })).not.toBeInTheDocument()
  })
})
