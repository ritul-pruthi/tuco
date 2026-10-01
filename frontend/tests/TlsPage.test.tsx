import '@testing-library/jest-dom/vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import Layout from '../src/components/Layout'
import TlsPage from '../src/pages/TlsPage'

const records = [
  { id: 'tls-1', investigation_id: 'abc', timestamp: '2026-09-30T10:00:01Z', source_ip: '10.0.0.5', source_port: 4000, destination_ip: '142.250.190.14', destination_port: 443, sni: 'example.com', tls_version: 'TLS 1.2', certificate_subject: 'CN=example.com', certificate_issuer: 'CN=Example CA', certificate_not_before: '2024-01-01T00:00:00Z', certificate_not_after: '2025-01-01T00:00:00Z' },
  { id: 'tls-2', investigation_id: 'abc', timestamp: '2026-09-30T10:00:02Z', source_ip: '10.0.0.6', source_port: 4001, destination_ip: '8.8.8.8', destination_port: 443, sni: 'api.example.com', tls_version: 'TLS 1.3', certificate_subject: 'CN=api.example.com', certificate_issuer: 'CN=Example CA', certificate_not_before: '2024-02-01T00:00:00Z', certificate_not_after: '2025-02-01T00:00:00Z' },
]

function renderPage() {
  return render(
    <MemoryRouter initialEntries={['/investigations/abc/tls']}>
      <Layout>
        <Routes>
          <Route path="/investigations/:id/tls" element={<TlsPage />} />
        </Routes>
      </Layout>
    </MemoryRouter>,
  )
}

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

describe('TlsPage', () => {
  it('renders TLS records and supporting metadata', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => records }))
    renderPage()
    expect((await screen.findAllByText('example.com')).length).toBeGreaterThan(0)
    expect((screen.getAllByText('TLS 1.2').length)).toBeGreaterThan(0)
    expect(screen.getByText('CN=example.com')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Evidence' })).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Observables' })).toHaveAttribute('href', '/investigations/abc/iocs')
    expect(screen.getByRole('columnheader', { name: 'Port' })).toHaveClass('tls-port-column')
    expect(screen.getByRole('columnheader', { name: 'Certificate' })).toHaveClass('tls-certificate-column')
    expect(screen.getByRole('columnheader', { name: 'Issuer' })).toHaveClass('tls-issuer-column')
    expect(screen.getAllByRole('cell', { name: '443' })[0]).toHaveClass('tls-port-column')
    expect(screen.getByRole('cell', { name: 'CN=example.com' })).toHaveClass('tls-certificate-column')
    expect(screen.getAllByRole('cell', { name: 'CN=Example CA' })[0]).toHaveClass('tls-issuer-column')
  })

  it('shows loading, empty, and error states', async () => {
    let resolveRequest: (value: unknown) => void = () => undefined
    vi.stubGlobal('fetch', vi.fn().mockReturnValue(new Promise((resolve) => { resolveRequest = resolve })))
    renderPage()
    expect(screen.getByText('Loading TLS records...')).toBeInTheDocument()
    resolveRequest({ ok: true, json: async () => [] })
    expect(await screen.findByText('No TLS records found in this capture.')).toBeInTheDocument()

    vi.restoreAllMocks()
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('Investigation not found')))
    renderPage()
    expect(await screen.findByRole('alert')).toHaveTextContent('Unable to load TLS records. Investigation not found')
  })

  it('filters records by search, version, and SNI', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => records }))
    renderPage()
    expect(await screen.findByRole('table')).toHaveTextContent('api.example.com')
    fireEvent.change(screen.getByRole('combobox', { name: 'Filter by TLS version' }), { target: { value: 'TLS 1.3' } })
    expect(screen.getByRole('table')).toHaveTextContent('api.example.com')
    expect(screen.getByRole('table')).not.toHaveTextContent('CN=example.com')
    fireEvent.change(screen.getByRole('combobox', { name: 'Filter by TLS version' }), { target: { value: 'all' } })
    fireEvent.change(screen.getByLabelText('Search TLS records'), { target: { value: 'CN=example.com' } })
    expect(screen.getByRole('table')).toHaveTextContent('CN=example.com')
  })
})
