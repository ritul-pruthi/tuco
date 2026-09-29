import '@testing-library/jest-dom/vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import FlowsPage from '../src/pages/FlowsPage'

const flows = [
  { id: 'flow-1', investigation_id: 'abc', src_ip: '10.0.0.5', src_port: 4000, dst_ip: '145.254.160.237', dst_port: 80, protocol: 'TCP', packets_sent: 4, packets_received: 3, bytes_sent: 1000, bytes_received: 2000, first_seen: '2026-09-30T10:00:01Z', last_seen: '2026-09-30T10:00:20Z', tcp_state: 'established' },
  { id: 'flow-2', investigation_id: 'abc', src_ip: '10.0.0.6', src_port: 5000, dst_ip: '10.0.0.7', dst_port: 53, protocol: 'UDP', packets_sent: 2, packets_received: 2, bytes_sent: 500, bytes_received: 500, first_seen: '2026-09-30T10:00:02Z', last_seen: '2026-09-30T10:00:21Z', tcp_state: null },
  { id: 'flow-3', investigation_id: 'abc', src_ip: '10.0.0.8', src_port: 0, dst_ip: '10.0.0.9', dst_port: 0, protocol: 'ICMP', packets_sent: 1, packets_received: 1, bytes_sent: 100, bytes_received: 100, first_seen: '2026-09-30T10:00:03Z', last_seen: '2026-09-30T10:00:22Z', tcp_state: null },
]

function renderPage(initialEntry = '/investigations/abc/connections') {
  return render(<MemoryRouter initialEntries={[initialEntry]}><Routes><Route path="/investigations/:id/connections" element={<FlowsPage />} /></Routes></MemoryRouter>)
}

afterEach(() => vi.restoreAllMocks())

describe('FlowsPage', () => {
  it('renders sorted flow rows and protocol labels', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => flows }))
    renderPage()
    expect(await screen.findByText('10.0.0.5:4000')).toBeInTheDocument()
    expect(screen.getByText('TCP')).toBeInTheDocument()
    expect(screen.getByText('UDP')).toBeInTheDocument()
    expect(screen.getByText('ICMP')).toBeInTheDocument()
  })

  it('filters flows by the host query parameter', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => flows }))
    renderPage('/investigations/abc/connections?host=10.0.0.5')
    expect(await screen.findByText('10.0.0.5:4000')).toBeInTheDocument()
    expect(screen.queryByText('10.0.0.6:5000')).not.toBeInTheDocument()
    expect(screen.getByText('Clear filter')).toBeInTheDocument()
  })

  it('renders the empty state', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => [] }))
    renderPage()
    expect(await screen.findByText('No connections found.')).toBeInTheDocument()
  })
})
