import '@testing-library/jest-dom/vitest'
import { cleanup, render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import DetectionDetailPage from '../src/pages/DetectionDetailPage'

const detection = { id: 'det-1', investigation_id: 'abc12345', rule_id: 'internal_recon_v1', title: 'Internal reconnaissance', severity: 'high', confidence: 'high', source_ip: '10.0.0.5', source_port: null, destination_ip: '10.0.0.15', destination_port: 80, timeframe_start: '2026-09-30T10:00:00Z', timeframe_end: '2026-09-30T10:00:10Z', observed_metric: '23 distinct destination ports in 10 seconds', observed_value: 23, threshold_description: '20 ports', threshold_value: 20, explanation: 'A host contacted many destinations.', evidence: [{ type: 'flow', id: 'flow-1' }, { type: 'dns', id: 'dns-1', timestamp: '2026-09-30T10:00:05Z' }], limitations: 'This is not proof of compromise.', created_at: '2026-09-30T10:01:00Z' }
const flow = { id: 'flow-1', investigation_id: 'abc12345', src_ip: '10.0.0.5', src_port: 40001, dst_ip: '10.0.0.15', dst_port: 80, protocol: 'TCP', packets_sent: 3, packets_received: 2, bytes_sent: 300, bytes_received: 200, first_seen: '2026-09-30T10:00:01Z', last_seen: '2026-09-30T10:00:02Z', tcp_state: 'SYN' }

function renderPage() {
  return render(<MemoryRouter initialEntries={['/investigations/abc12345/detections/det-1']}><Routes><Route path="/investigations/:id/detections/:detectionId" element={<DetectionDetailPage />} /></Routes></MemoryRouter>)
}

function mockFetch(data: unknown = [detection]) {
  vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string) => {
    if (url.endsWith('/detections')) return Promise.resolve({ ok: true, json: async () => data })
    if (url.endsWith('/flows')) return Promise.resolve({ ok: true, json: async () => [flow] })
    return Promise.resolve({ ok: true, json: async () => [] })
  }))
}

afterEach(() => { cleanup(); vi.restoreAllMocks() })

describe('DetectionDetailPage', () => {
  it('renders detection details and evidence', async () => {
    mockFetch()
    renderPage()
    expect(await screen.findByText('Internal reconnaissance')).toBeInTheDocument()
    expect(screen.getByText('10.0.0.5:40001 -> 10.0.0.15:80 · TCP · 5 packets · 0.5 KB')).toBeInTheDocument()
    expect(screen.getByText('dns-1')).toBeInTheDocument()
    expect(screen.getByText((content) => content.includes('Detailed view coming in a later sub-task'))).toBeInTheDocument()
  })

  it('shows a not found state for a missing detection', async () => {
    mockFetch([])
    renderPage()
    expect(await screen.findByRole('heading', { name: 'Detection not found' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Back to detections' })).toHaveAttribute('href', '/investigations/abc12345/detections')
  })

  it('renders related navigation links', async () => {
    mockFetch()
    renderPage()
    await screen.findByText('Internal reconnaissance')
    expect(screen.getByRole('link', { name: 'All connections for 10.0.0.5' })).toHaveAttribute('href', '/investigations/abc12345/connections?host=10.0.0.5')
    expect(screen.getByRole('link', { name: 'Timeline' })).toHaveAttribute('href', '/investigations/abc12345/timeline')
    expect(screen.getByRole('link', { name: 'Back to detections' })).toHaveAttribute('href', '/investigations/abc12345/detections')
  })
})
