import '@testing-library/jest-dom/vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import IocsPage from '../src/pages/IocsPage'

const iocs = [
  { id: 'ipv4-1', investigation_id: 'abc12345', ioc_type: 'ipv4', value: '10.0.0.5', first_seen: '2026-09-30T10:00:00Z', last_seen: '2026-09-30T10:01:00Z', occurrences: 4, scope: 'internal', evidence_type: 'host', evidence_ids: ['host-1'] },
  { id: 'ipv6-1', investigation_id: 'abc12345', ioc_type: 'ipv6', value: '2001:db8::1', first_seen: '2026-09-30T10:00:00Z', last_seen: '2026-09-30T10:01:00Z', occurrences: 2, scope: 'external', evidence_type: 'flow', evidence_ids: ['flow-1'] },
  { id: 'domain-1', investigation_id: 'abc12345', ioc_type: 'domain', value: 'example.com', first_seen: '2026-09-30T10:00:00Z', last_seen: '2026-09-30T10:01:00Z', occurrences: 3, scope: 'n/a', evidence_type: 'mixed', evidence_ids: ['dns-1', 'http-1'] },
  { id: 'url-1', investigation_id: 'abc12345', ioc_type: 'url', value: `http://example.com/${'a'.repeat(90)}`, first_seen: '2026-09-30T10:00:00Z', last_seen: '2026-09-30T10:01:00Z', occurrences: 1, scope: 'n/a', evidence_type: 'http', evidence_ids: ['http-1'] },
  { id: 'agent-1', investigation_id: 'abc12345', ioc_type: 'user_agent', value: 'curl/8.0', first_seen: '2026-09-30T10:00:00Z', last_seen: '2026-09-30T10:01:00Z', occurrences: 1, scope: 'n/a', evidence_type: 'http', evidence_ids: ['http-1'] },
]

function renderPage() {
  return render(<MemoryRouter initialEntries={['/investigations/abc12345/iocs']}><Routes><Route path="/investigations/:id/iocs" element={<IocsPage />} /></Routes></MemoryRouter>)
}

afterEach(() => vi.restoreAllMocks())

describe('IocsPage', () => {
  it('renders present IOC sections and omits empty types', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => iocs }))
    renderPage()
    expect(await screen.findByRole('heading', { name: /IPv4 addresses/ })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: /IPv6 addresses/ })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: /Domains/ })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: /URLs/ })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: /User agents/ })).toBeInTheDocument()
  })

  it('shows scope and links host evidence', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => [iocs[0]] }))
    renderPage()
    expect(await screen.findByText('internal')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Host records' })).toHaveAttribute('href', '/investigations/abc12345/hosts')
  })

  it('truncates long URLs while preserving the full title', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => [iocs[3]] }))
    renderPage()
    const url = await screen.findByTitle(iocs[3].value)
    expect(url).toHaveTextContent(`${iocs[3].value.slice(0, 80)}...`)
    expect(url.textContent).toHaveLength(83)
  })

  it('renders mixed evidence as muted text', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => [iocs[2]] }))
    renderPage()
    expect(await screen.findByText('mixed sources')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'mixed sources' })).not.toBeInTheDocument()
  })

  it('renders the empty state', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => [] }))
    renderPage()
    expect(await screen.findByText('No indicators extracted from this capture.')).toBeInTheDocument()
  })
})
