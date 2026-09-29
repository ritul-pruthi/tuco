import '@testing-library/jest-dom/vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import DetectionsPage from '../src/pages/DetectionsPage'

const detections = [
  { id: 'det-1', investigation_id: 'abc12345', rule_id: 'internal_recon_v1', title: 'Internal reconnaissance', severity: 'high', confidence: 'high', source_ip: '10.0.0.5', source_port: null, destination_ip: '10.0.0.15', destination_port: 80, timeframe_start: '2026-09-30T10:00:00Z', timeframe_end: '2026-09-30T10:00:10Z', observed_metric: '23 distinct destination ports in 10 seconds', observed_value: 23, threshold_description: '20 ports', threshold_value: 20, explanation: 'A host contacted many destinations.', evidence: [{ type: 'flow', id: 'flow-1' }], limitations: 'This is not proof of compromise.', created_at: '2026-09-30T10:01:00Z' },
  { id: 'det-2', investigation_id: 'abc12345', rule_id: 'beacon_v1', title: 'Periodic communication', severity: 'low', confidence: 'medium', source_ip: '10.0.0.5', source_port: 4000, destination_ip: '8.8.8.8', destination_port: 443, timeframe_start: '2026-09-30T10:00:00Z', timeframe_end: '2026-09-30T10:01:00Z', observed_metric: '5 regular intervals', observed_value: 5, threshold_description: '5 intervals', threshold_value: 5, explanation: 'Regular communication was observed.', evidence: [], limitations: 'Timing alone is not malicious.', created_at: '2026-09-30T10:01:00Z' },
]

function renderPage() {
  return render(<MemoryRouter initialEntries={['/investigations/abc12345/detections']}><Routes><Route path="/investigations/:id/detections" element={<DetectionsPage />} /></Routes></MemoryRouter>)
}

afterEach(() => vi.restoreAllMocks())

describe('DetectionsPage', () => {
  it('renders detection cards and evidence links', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => detections }))
    renderPage()
    expect(await screen.findByText('Internal reconnaissance')).toBeInTheDocument()
    expect(screen.getByText('23 distinct destination ports in 10 seconds')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'View Evidence (1)' })).toHaveAttribute('href', '/investigations/abc12345/detections/det-1')
  })

  it('renders the required empty state', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => [] }))
    renderPage()
    expect(await screen.findByText('No detections fired on this capture.')).toBeInTheDocument()
    expect(screen.getByText("This doesn't mean the capture is benign — it means no known patterns matched.")).toBeInTheDocument()
  })

  it('uses the severity class for each detection', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => detections }))
    renderPage()
    await screen.findByText('Internal reconnaissance')
    expect(screen.getByText('high', { selector: '.severity-badge' })).toHaveClass('severity-high')
    expect(screen.getByText('low', { selector: '.severity-badge' })).toHaveClass('severity-low')
  })
})
