import '@testing-library/jest-dom/vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import DnsPage from '../src/pages/DnsPage'

const records = [
  { id: 'dns-1', investigation_id: 'abc', timestamp: '2026-09-30T10:00:01Z', source_ip: '10.0.0.5', destination_ip: '10.0.0.1', query: 'example.com', query_type: 'A', response_code: 0, answers: ['93.184.216.34'] },
  { id: 'dns-2', investigation_id: 'abc', timestamp: '2026-09-30T10:00:02Z', source_ip: '10.0.0.6', destination_ip: '10.0.0.1', query: 'missing.example.com', query_type: 'AAAA', response_code: 3, answers: [] },
]

function renderPage() {
  return render(<MemoryRouter initialEntries={['/investigations/abc/dns']}><Routes><Route path="/investigations/:id/dns" element={<DnsPage />} /></Routes></MemoryRouter>)
}

afterEach(() => vi.restoreAllMocks())

describe('DnsPage', () => {
  it('renders DNS records with investigation fields', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => records }))
    renderPage()
    expect(await screen.findByText('example.com')).toBeInTheDocument()
    expect(screen.getByText('2026-09-30 10:00:01')).toBeInTheDocument()
    expect(screen.getByText('10.0.0.5')).toBeInTheDocument()
    expect(screen.getAllByText('10.0.0.1')).toHaveLength(2)
    expect(screen.getByText('93.184.216.34')).toBeInTheDocument()
  })

  it('filters records by search text, query type, and response code', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => records }))
    renderPage()
    expect(await screen.findByText('example.com')).toBeInTheDocument()
    fireEvent.change(screen.getByRole('combobox', { name: 'Filter by query type' }), { target: { value: 'AAAA' } })
    expect(screen.getByText('missing.example.com')).toBeInTheDocument()
    expect(screen.queryByText('93.184.216.34')).not.toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Search DNS records'), { target: { value: 'missing' } })
    expect(screen.getByText('missing.example.com')).toBeInTheDocument()
  })

  it('renders loading, empty, and error states', async () => {
    let resolveRequest: (value: unknown) => void = () => undefined
    vi.stubGlobal('fetch', vi.fn().mockReturnValue(new Promise((resolve) => { resolveRequest = resolve })))
    renderPage()
    expect(screen.getByText('Loading DNS records...')).toBeInTheDocument()
    resolveRequest({ ok: true, json: async () => [] })
    expect(await screen.findByText('No DNS records found in this capture.')).toBeInTheDocument()

    vi.restoreAllMocks()
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('Investigation not found')))
    renderPage()
    expect(await screen.findByRole('alert')).toHaveTextContent('Unable to load DNS records. Investigation not found')
  })
})
