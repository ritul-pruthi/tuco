import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useParams } from 'react-router-dom'
import { generateAiSummary, getAiReports } from '../services/api'
import type { AiReportRecord, ValidationWarning } from '../types/api'
import { countBySeverity, getExplanation, getSeverity, reportCopyText } from '../utils/warnings'

function formatTimestamp(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return `${date.toISOString().slice(0, 16).replace('T', ' ')} UTC`
}

function fieldWarnings(field: string, warnings: ValidationWarning[]): ValidationWarning[] {
  return warnings.filter((warning) => warning.field === field)
}

function sectionWarnings(prefix: string, warnings: ValidationWarning[]): ValidationWarning[] {
  return warnings.filter((warning) => warning.field === prefix || warning.field.startsWith(`${prefix}[`))
}

function fieldId(field: string): string {
  return `ai-report-field-${field.replaceAll(/[^a-zA-Z0-9]+/g, '-')}`
}

function WarningMarker({ warnings }: { warnings: ValidationWarning[] }) {
  if (warnings.length === 0) return null
  const severities = warnings.map((warning) => getSeverity(warning.type))
  const highest = severities.includes('critical') ? 'critical' : severities.includes('warning') ? 'warning' : 'info'
  return <span aria-label={`${warnings.length} validation warning${warnings.length > 1 ? 's' : ''}`} className="warning-marker" data-severity={highest} title={warnings.map((warning) => warning.value).join(', ')}>⚠</span>
}

function WarningCards({ warnings, onJump }: { warnings: ValidationWarning[]; onJump: (field: string) => void }) {
  return <div className="ai-report-warning-cards">{warnings.map((warning, index) => {
    const severity = getSeverity(warning.type)
    return <article className="ai-report-warning-card" data-severity={severity} key={`${warning.field}-${warning.type}-${index}`}>
      <div className="ai-report-warning-card__tier">{severity}</div>
      <p className="ai-report-warning-card__explanation">{getExplanation(warning)}</p>
      <p className="ai-report-warning-card__meta"><strong>Field:</strong> <code>{warning.field}</code> · <strong>Value:</strong> <code>{warning.value}</code></p>
      <p className="ai-report-warning-card__meta">Context: <q>{warning.context.slice(0, 120)}{warning.context.length > 120 ? '…' : ''}</q></p>
      <button className="text-button" type="button" onClick={() => onJump(warning.field)}>Jump to field</button>
    </article>
  })}</div>
}

export function AiReportPage() {
  const { id = '' } = useParams<{ id: string }>()
  const [reports, setReports] = useState<AiReportRecord[]>([])
  const [selectedReportId, setSelectedReportId] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [generating, setGenerating] = useState(false)
  const [generatingElapsed, setGeneratingElapsed] = useState(0)
  const [expandedWarnings, setExpandedWarnings] = useState(false)
  const [highlightedField, setHighlightedField] = useState<string | null>(null)
  const requestSeq = useRef(0)

  const fetchReports = useCallback(() => {
    const seq = ++requestSeq.current
    setLoading(true)
    setError(null)
    return getAiReports(id)
      .then((loadedReports) => {
        if (seq !== requestSeq.current) return
        setReports(loadedReports)
        setSelectedReportId((current) => current && loadedReports.some((report) => report.id === current) ? current : loadedReports[0]?.id ?? '')
      })
      .catch((loadError: unknown) => {
        if (seq !== requestSeq.current) return
        setError(loadError instanceof Error ? loadError.message : 'Unable to load AI reports.')
      })
      .finally(() => {
        if (seq === requestSeq.current) setLoading(false)
      })
  }, [id])

  useEffect(() => {
    void Promise.resolve().then(fetchReports)
  }, [fetchReports])

  useEffect(() => {
    if (!generating) return
    const startedAt = Date.now()
    const timer = window.setInterval(() => setGeneratingElapsed(Math.floor((Date.now() - startedAt) / 1000)), 1000)
    return () => window.clearInterval(timer)
  }, [generating])

  const selectedReport = reports.find((report) => report.id === selectedReportId) ?? null
  const visibleWarnings = useMemo(() => selectedReport?.warnings.filter((warning) => getSeverity(warning.type) !== 'suppressed') ?? [], [selectedReport])
  const severityCounts = countBySeverity(visibleWarnings)
  const bannerSeverity = severityCounts.critical > 0 ? 'critical' : severityCounts.warning > 0 ? 'warning' : 'info'

  const jumpToField = (field: string) => {
    const target = document.getElementById(fieldId(field))
    target?.scrollIntoView({ behavior: 'smooth', block: 'center' })
    setHighlightedField(field)
    window.setTimeout(() => setHighlightedField((current) => current === field ? null : current), 1800)
  }

  const handleGenerate = async () => {
    setGenerating(true)
    setGeneratingElapsed(0)
    setError(null)
    try {
      const generated = await generateAiSummary(id)
      const loadedReports = await getAiReports(id)
      setReports(loadedReports)
      setSelectedReportId(generated.report_id)
    } catch (generateError: unknown) {
      setError(generateError instanceof Error ? generateError.message : 'Unable to generate an AI report.')
    } finally {
      setGenerating(false)
    }
  }

  const copyReport = async (withWarnings: boolean) => {
    if (!selectedReport) return
    await navigator.clipboard.writeText(reportCopyText(selectedReport.report, withWarnings, selectedReport.warnings))
  }

  const downloadReport = () => {
    if (!selectedReport) return
    const blob = new Blob([reportCopyText(selectedReport.report, true, selectedReport.warnings)], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `tuco-ai-report-${selectedReport.id}.md`
    link.click()
    window.setTimeout(() => URL.revokeObjectURL(url), 100)
  }

  if (loading) return <div className="detail-page ai-report-page"><p className="detail-state">Loading AI report history...</p></div>

  return <div className="detail-page ai-report-page">
    <header className="ai-report-header">
      <div><p className="eyebrow">Evidence interpretation</p><h1>AI Report</h1><p className="detail-subtitle">Investigation {id.slice(0, 8)}</p></div>
      <div className="ai-report-actions">
        {reports.length > 0 && <label className="ai-report-history-dropdown">History
          <select aria-label="Report history" value={selectedReportId} onChange={(event) => setSelectedReportId(event.target.value)}>
            {reports.map((report) => <option key={report.id} value={report.id}>{formatTimestamp(report.created_at)} ({report.warnings.filter((warning) => getSeverity(warning.type) !== 'suppressed').length} warnings)</option>)}
          </select>
        </label>}
        <button className="primary-button" disabled={generating} type="button" onClick={handleGenerate}>{generating ? `Generating... ${generatingElapsed}s` : reports.length ? 'Generate New Report' : 'Generate AI Report'}</button>
      </div>
    </header>
    {error && <section className="ai-report-error" role="alert"><p>Unable to load the AI report. {error}</p><button className="text-button" type="button" onClick={() => void fetchReports()}>Retry</button></section>}
    {generating && <p className="ai-report-generating" aria-live="polite">Generating report... {generatingElapsed}s{generatingElapsed > 120 && <span> AI generation may take 30-90s on first run.</span>}</p>}
    {!selectedReport && !generating && !error && <section className="ai-report-empty"><h2>No AI reports yet.</h2><p>Generate a report to summarize the verified evidence in this investigation.</p><button className="primary-button" type="button" onClick={handleGenerate}>Generate AI Report</button></section>}
    {selectedReport && <article>
      {visibleWarnings.length > 0 && <section className="ai-report-warning-banner" data-severity={bannerSeverity}>
        <button type="button" onClick={() => setExpandedWarnings((expanded) => !expanded)} aria-expanded={expandedWarnings}><strong>Validation warnings</strong><span>{severityCounts.critical > 0 && `${severityCounts.critical} critical`}{severityCounts.critical > 0 && severityCounts.warning > 0 && ' · '}{severityCounts.warning > 0 && `${severityCounts.warning} warnings`}{severityCounts.info > 0 && ` · ${severityCounts.info} info`}</span></button>
        {expandedWarnings && <WarningCards onJump={jumpToField} warnings={visibleWarnings} />}
      </section>}
      <div className="ai-report-body">
        <section className={`ai-report-section ${highlightedField === 'summary' ? 'ai-report-highlighted' : ''}`} id={fieldId('summary')}><header className="ai-report-section__header"><h2>Summary</h2>{sectionWarnings('summary', visibleWarnings).length > 0 && <span className="ai-report-section__badge">⚠ {sectionWarnings('summary', visibleWarnings).length}</span>}</header><p>{selectedReport.report.summary}<WarningMarker warnings={fieldWarnings('summary', visibleWarnings)} /></p></section>
        <section className="ai-report-section"><header className="ai-report-section__header"><h2>Key Findings</h2>{sectionWarnings('key_findings', visibleWarnings).length > 0 && <span className="ai-report-section__badge">⚠ {sectionWarnings('key_findings', visibleWarnings).length}</span>}</header><ul>{selectedReport.report.key_findings.map((finding, index) => { const field = `key_findings[${index}]`; return <li className={highlightedField === field ? 'ai-report-highlighted' : ''} id={fieldId(field)} key={field}><WarningMarker warnings={fieldWarnings(field, visibleWarnings)} />{finding}</li> })}</ul></section>
        <section className="ai-report-section"><header className="ai-report-section__header"><h2>MITRE ATT&amp;CK Context</h2>{sectionWarnings('mitre_context', visibleWarnings).length > 0 && <span className="ai-report-section__badge">⚠ {sectionWarnings('mitre_context', visibleWarnings).length}</span>}</header><div className="table-wrap"><table className="data-table ai-report-mitre-table"><thead><tr><th>ID</th><th>Name</th><th>Triggered by</th></tr></thead><tbody>{selectedReport.report.mitre_context.map((technique) => <tr key={technique.id}><td className="technical">{technique.id}</td><td>{technique.name}</td><td className="technical">{technique.rule_ids?.join(', ') ?? ''}</td></tr>)}</tbody></table></div></section>
        <section className="ai-report-section"><header className="ai-report-section__header"><h2>Recommended Next Steps</h2>{sectionWarnings('recommended_next_steps', visibleWarnings).length > 0 && <span className="ai-report-section__badge">⚠ {sectionWarnings('recommended_next_steps', visibleWarnings).length}</span>}</header><ul>{selectedReport.report.recommended_next_steps.map((step, index) => { const field = `recommended_next_steps[${index}]`; return <li className={highlightedField === field ? 'ai-report-highlighted' : ''} id={fieldId(field)} key={field}><WarningMarker warnings={fieldWarnings(field, visibleWarnings)} />{step}</li> })}</ul></section>
        <section className="ai-report-section"><header className="ai-report-section__header"><h2>Limitations</h2>{sectionWarnings('limitations', visibleWarnings).length > 0 && <span className="ai-report-section__badge">⚠ {sectionWarnings('limitations', visibleWarnings).length}</span>}</header><ul>{selectedReport.report.limitations.map((limitation, index) => { const field = `limitations[${index}]`; return <li className={highlightedField === field ? 'ai-report-highlighted' : ''} id={fieldId(field)} key={field}><WarningMarker warnings={fieldWarnings(field, visibleWarnings)} />{limitation}</li> })}</ul></section>
      </div>
      <footer className="ai-report-footer"><p>TUCO policy: Absence of detection is not evidence of absence of compromise.</p><p className="ai-report-metadata">Generated <span>{formatTimestamp(selectedReport.created_at)}</span> · <span>{selectedReport.model}</span> · <span>prompt {selectedReport.prompt_version}</span></p><div className="ai-report-actions"><button className="text-button" type="button" onClick={() => void copyReport(false)}>Copy Report</button><button className="text-button" type="button" onClick={() => void copyReport(true)}>Copy with Warnings</button><button className="text-button" type="button" onClick={downloadReport}>Download .md</button></div></footer>
    </article>}
  </div>
}

export default AiReportPage
