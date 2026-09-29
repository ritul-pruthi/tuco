import '@testing-library/jest-dom/vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import HostsPage from '../src/pages/HostsPage'

const hosts = [
  { id: 'host-1', investigation_id: 'abc12345', ip: '10.0.0.1', mac: null, scope: 'internal', packets_sent: 5, packets_received: 5, bytes_sent: 1024, bytes_received: 2048, unique_destinations: 1, unique_ports: 2, first_seen: '2026-09-30T10:00:01Z', last_seen: '2026-09-30T10:00:20Z' },
  { id: 'host-2', investigation_id: 'abc12345', ip: '10.0.0.2', mac: '00:11:22:33:44:55', scope: 'internal', packets_sent: 20, packets_received: 15, bytes_sent: 1024 * 1024, bytes_received: 2048, unique_destinations: 2, unique_ports: 3, first_seen: '2026-09-30T10:00:02Z', last_seen: '2026-09-30T10:00:21Z' },
]

function renderPage() {
  return render(<MemoryRouter initialEntries={['/investigations/abc12345/hosts']}><Routes><Route path="/investigations/:id/hosts" element={<HostsPage />} /></Routes></MemoryRouter>)
}

afterEach(() => vi.restoreAllMocks())

describe('HostsPage', () => {
  it('renders hosts sorted by total packets descending', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => hosts }))
    renderPage()
    expect(await screen.findByText('10.0.0.2')).toBeInTheDocument()
    const rows = screen.getAllByRole('row')
    expect(rows[1]).toHaveTextContent('10.0.0.2')
    expect(rows[2]).toHaveTextContent('10.0.0.1')
  })

  it('renders the empty state', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => [] }))
    renderPage()
    expect(await screen.findByText('No hosts found in this capture.')).toBeInTheDocument()
  })

  it('renders a friendly load error', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('Network unavailable')))
    renderPage()
    expect(await screen.findByRole('alert')).toHaveTextContent('Unable to load hosts.')
  })
})
