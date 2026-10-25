import '@testing-library/jest-dom/vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import AiReportPage from '../src/pages/AiReportPage'
import type { AiReportRecord, AiSummaryResponse } from '../src/types/api'

const { getAiReports, generateAiSummary } = vi.hoisted(() => ({
  getAiReports: vi.fn<() => Promise<AiReportRecord[]>>(),
  generateAiSummary: vi.fn<() => Promise<AiSummaryResponse>>(),
}))

vi.mock('../src/services/api', () => ({ getAiReports, generateAiSummary }))

const report = (id: string, summary: string, warnings: AiReportRecord['warnings'] = []): AiReportRecord => ({
  id,
  investigation_id: 'inv-1',
  model: 'qwen3.5:4b',
  prompt_version: 'v5',
  report: {
    summary,
    key_findings: ['Observed finding'],
    mitre_context: [{ id: 'T1046', name: 'Network Service Discovery', rule_ids: ['port_scan_v1'] }],
    recommended_next_steps: ['Review the source host'],
    limitations: ['The capture may not contain all relevant activity.'],
  },
  markdown: '# ignored',
  warnings,
  created_at: '2026-10-24T18:03:00Z',
})

function renderPage() {
  return render(<MemoryRouter initialEntries={['/investigations/inv-1/ai-report']}><Routes><Route element={<AiReportPage />} path="/investigations/:id/ai-report" /></Routes></MemoryRouter>)
}

describe('AiReportPage', () => {
  beforeEach(() => {
    vi.resetAllMocks()
  })

  it('shows the empty state', async () => {
    getAiReports.mockResolvedValue([])
    renderPage()

    expect(await screen.findByText('No AI reports yet.')).toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: 'Generate AI Report' })).not.toHaveLength(0)
  })

  it('shows the loading state', () => {
    getAiReports.mockReturnValue(new Promise(() => undefined))
    renderPage()

    expect(screen.getByText('Loading AI report history...')).toBeInTheDocument()
  })

  it('renders all report sections and the footer without a warning banner', async () => {
    getAiReports.mockResolvedValue([report('one', 'Clean summary')])
    renderPage()

    expect(await screen.findByText('Clean summary')).toBeInTheDocument()
    expect(screen.getByText('Key Findings')).toBeInTheDocument()
    expect(screen.getByText('MITRE ATT&CK Context')).toBeInTheDocument()
    expect(screen.getByText('Recommended Next Steps')).toBeInTheDocument()
    expect(screen.getByText('Limitations')).toBeInTheDocument()
    expect(screen.queryByText('Validation warnings')).not.toBeInTheDocument()
    expect(screen.getByText('TUCO policy: Absence of detection is not evidence of absence of compromise.')).toBeInTheDocument()
  })

  it('shows warning cards and markers while suppressing the required limitation warning', async () => {
    getAiReports.mockResolvedValue([report('one', 'Summary', [
      { type: 'fabricated_number', field: 'key_findings[0]', value: '42', context: 'Observed finding with 42 events.' },
      { type: 'directive_phrasing', field: 'recommended_next_steps[0]', value: 'Block', context: 'Block the source host.' },
      { type: 'missing_required_limitation', field: 'limitations', value: 'absence-of-detection-disclaimer', context: '' },
    ])])
    renderPage()

    expect(await screen.findByText('Validation warnings')).toBeInTheDocument()
    expect(screen.getByText('1 critical · 1 warnings')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Validation warnings'))
    expect(screen.getByText(/Number not present in the evidence bundle/)).toBeInTheDocument()
    expect(screen.getAllByTitle('42')).toHaveLength(1)
    expect(screen.queryByText('absence-of-detection-disclaimer')).not.toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: 'Jump to field' })).not.toHaveLength(0)
  })

  it('changes the selected report from history', async () => {
    getAiReports.mockResolvedValue([report('one', 'First report'), report('two', 'Second report')])
    renderPage()

    expect(await screen.findByText('First report')).toBeInTheDocument()
    fireEvent.change(screen.getByRole('combobox', { name: 'Report history' }), { target: { value: 'two' } })
    expect(screen.getByText('Second report')).toBeInTheDocument()
  })

  it('generates a report and selects the new history entry', async () => {
    getAiReports.mockResolvedValueOnce([]).mockResolvedValueOnce([report('new', 'Generated report')])
    generateAiSummary.mockResolvedValue({ report_id: 'new', report: report('new', 'Generated report').report, markdown: '', provider: 'ollama', model: 'qwen3.5:4b', prompt_version: 'v5', generated_at: '2026-10-24T18:03:00Z', warnings: [] })
    renderPage()

    fireEvent.click((await screen.findAllByRole('button', { name: 'Generate AI Report' }))[0])
    expect(await screen.findByText('Generated report')).toBeInTheDocument()
    expect(generateAiSummary).toHaveBeenCalledWith('inv-1')
  })

  it('shows generation errors', async () => {
    getAiReports.mockResolvedValue([])
    generateAiSummary.mockRejectedValue(new Error('AI provider is unavailable'))
    renderPage()

    fireEvent.click((await screen.findAllByRole('button', { name: 'Generate AI Report' }))[0])
    expect(await screen.findByRole('alert')).toHaveTextContent('AI provider is unavailable')
    await waitFor(() => expect(generateAiSummary).toHaveBeenCalled())
  })
})
