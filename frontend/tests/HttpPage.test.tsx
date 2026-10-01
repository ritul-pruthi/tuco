import '@testing-library/jest-dom/vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import HttpPage from '../src/pages/HttpPage'

const records = [
  { id: 'http-1', investigation_id: 'abc', timestamp: '2026-09-30T10:00:01Z', source_ip: '10.0.0.5', source_port: 4000, destination_ip: '145.254.160.237', destination_port: 80, method: 'GET', host: 'example.com', path: '/index.html', user_agent: 'Mozilla/5.0', status_code: 200 },
  { id: 'http-2', investigation_id: 'abc', timestamp: '2026-09-30T10:00:02Z', source_ip: '10.0.0.6', source_port: 4001, destination_ip: '145.254.160.238', destination_port: 80, method: 'POST', host: 'upload.example.com', path: '/submit', user_agent: 'curl/8.0', status_code: 404 },
]

function renderPage() {
  return render(<MemoryRouter initialEntries={['/investigations/abc/http']}><Routes><Route path="/investigations/:id/http" element={<HttpPage />} /></Routes></MemoryRouter>)
}

afterEach(() => vi.restoreAllMocks())

describe('HttpPage', () => {
  it('renders HTTP records and important evidence fields', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => records }))
    renderPage()
    const table = await screen.findByRole('table')
    expect(table).toHaveTextContent('example.com')
    expect(table).toHaveTextContent('GET')
    expect(table).toHaveTextContent('/index.html')
    expect(table).toHaveTextContent('200')
    expect(table).toHaveTextContent('Mozilla/5.0')
  })

  it('shows loading and empty states', async () => {
    let resolveRequest: (value: unknown) => void = () => undefined
    vi.stubGlobal('fetch', vi.fn().mockReturnValue(new Promise((resolve) => { resolveRequest = resolve })))
    renderPage()
    expect(screen.getByText('Loading HTTP records...')).toBeInTheDocument()
    resolveRequest({ ok: true, json: async () => [] })
    expect(await screen.findByText('No HTTP records found in this capture.')).toBeInTheDocument()
  })

  it('shows a user-facing error state', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('Investigation not found')))
    renderPage()
    expect(await screen.findByRole('alert')).toHaveTextContent('Unable to load HTTP records. Investigation not found')
  })

  it('filters by search, method, status, and observed host', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => records }))
    renderPage()
    expect(await screen.findByRole('table')).toHaveTextContent('/index.html')
    fireEvent.change(screen.getByRole('combobox', { name: 'Filter by HTTP method' }), { target: { value: 'POST' } })
    expect(screen.getByRole('table')).toHaveTextContent('/submit')
    expect(screen.getByRole('table')).not.toHaveTextContent('/index.html')
    fireEvent.change(screen.getByRole('combobox', { name: 'Filter by status code' }), { target: { value: '404' } })
    fireEvent.change(screen.getByLabelText('Search HTTP records'), { target: { value: 'upload.example.com' } })
    expect(screen.getByRole('table')).toHaveTextContent('upload.example.com')
    fireEvent.change(screen.getByRole('combobox', { name: 'Filter by HTTP host' }), { target: { value: 'example.com' } })
    expect(screen.getByText('No HTTP records found in this capture.')).toBeInTheDocument()
  })
})
