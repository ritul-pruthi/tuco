import '@testing-library/jest-dom/vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import UploadPage from '../src/pages/UploadPage'

const investigation = {
  id: 'abc123',
  filename: 'http.pcap',
  format: 'pcap',
  size_bytes: 2048,
  packet_count: 12,
  started_at: '2026-09-30T10:00:00Z',
  ended_at: '2026-09-30T10:01:00Z',
  duration_seconds: 60,
  status: 'aggregated',
  created_at: '2026-09-30T10:02:00Z',
}

function renderPage() {
  return render(
    <MemoryRouter>
      <UploadPage />
    </MemoryRouter>,
  )
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('UploadPage', () => {
  it('renders filenames from recent investigations', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ items: [investigation, { ...investigation, id: 'def456', filename: 'dns_port.pcap' }] }),
    }))

    renderPage()

    expect(await screen.findByText('http.pcap')).toBeInTheDocument()
    expect(screen.getByText('dns_port.pcap')).toBeInTheDocument()
  })

  it('renders the empty state when there are no investigations', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ items: [], total: 0, limit: 100, offset: 0 }),
    }))

    renderPage()

    expect(await screen.findByText('No investigations yet. Upload a capture above to begin.')).toBeInTheDocument()
  })

  it('renders an API error', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: false,
      status: 503,
      json: async () => ({ detail: 'Backend unavailable' }),
    }))

    renderPage()

    expect(await screen.findByRole('alert')).toHaveTextContent('Backend unavailable')
  })

  it('uploads the selected file as multipart form data', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: async () => ({ items: [] }) })
      .mockResolvedValueOnce({ ok: true, json: async () => investigation })
    vi.stubGlobal('fetch', fetchMock)
    renderPage()

    const file = new File(['packet data'], 'capture.pcap', { type: 'application/vnd.tcpdump.pcap' })
    fireEvent.change(screen.getByLabelText('Capture file'), { target: { files: [file] } })
    fireEvent.click(screen.getByRole('button', { name: 'Upload capture' }))

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2))
    expect(fetchMock.mock.calls[1][0]).toBe('http://localhost:8000/api/investigations')
    const request = fetchMock.mock.calls[1][1] as RequestInit
    expect(request.method).toBe('POST')
    expect(request.body).toBeInstanceOf(FormData)
    expect((request.body as FormData).get('file')).toBe(file)
  })
})
