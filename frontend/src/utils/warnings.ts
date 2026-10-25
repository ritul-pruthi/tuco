import type { AiReport, ValidationWarning } from '../types/api'

export type WarningSeverity = 'critical' | 'warning' | 'info' | 'suppressed'

const explanations: Record<string, string> = {
  banned_word: 'Assertion word. The report should describe observed behavior, not draw conclusions.',
  fabricated_number: 'Number not present in the evidence bundle. All numeric values must come from the data.',
  directive_phrasing: 'Directive phrasing. The AI should recommend investigation, not dictate actions.',
  speculation_marker: 'Speculative phrasing. The report should describe observations, not interpretations.',
}

export function getSeverity(type: string): WarningSeverity {
  if (['fabricated_number', 'unknown_ip', 'unknown_rule_id', 'unknown_technique_id'].includes(type)) return 'critical'
  if (['banned_word', 'directive_phrasing'].includes(type)) return 'warning'
  if (type === 'speculation_marker') return 'info'
  if (type === 'missing_required_limitation') return 'suppressed'
  return 'info'
}

export function getExplanation(warning: ValidationWarning): string {
  if (warning.type.startsWith('unknown_')) return `${warning.value} does not appear in the evidence bundle.`
  return explanations[warning.type] ?? 'This report field did not pass validation against the evidence bundle.'
}

export function groupWarningsByField(warnings: ValidationWarning[]): Map<string, ValidationWarning[]> {
  const grouped = new Map<string, ValidationWarning[]>()
  warnings.filter((warning) => getSeverity(warning.type) !== 'suppressed').forEach((warning) => {
    const fieldWarnings = grouped.get(warning.field) ?? []
    fieldWarnings.push(warning)
    grouped.set(warning.field, fieldWarnings)
  })
  return grouped
}

export function countBySeverity(warnings: ValidationWarning[]): { critical: number; warning: number; info: number } {
  return warnings.reduce((counts, warning) => {
    const severity = getSeverity(warning.type)
    if (severity !== 'suppressed') counts[severity] += 1
    return counts
  }, { critical: 0, warning: 0, info: 0 })
}

function reportLines(report: AiReport): string[] {
  return [
    '# AI Report',
    '',
    '## Summary',
    report.summary,
    '',
    '## Key Findings',
    ...report.key_findings.map((finding) => `- ${finding}`),
    '',
    '## MITRE ATT&CK Context',
    ...report.mitre_context.map((technique) => `- ${technique.id}: ${technique.name}${technique.rule_ids?.length ? ` (triggered by: ${technique.rule_ids.join(', ')})` : ''}`),
    ...(report.mitre_context.length === 0 ? ['No MITRE ATT&CK techniques mapped from current detections.'] : []),
    '',
    '## Recommended Next Steps',
    ...report.recommended_next_steps.map((step) => `- ${step}`),
    '',
    '## Limitations',
    ...report.limitations.map((limitation) => `- ${limitation}`),
    '',
    'TUCO policy: Absence of detection is not evidence of absence of compromise.',
  ]
}

export function reportCopyText(report: AiReport, includeWarnings: boolean, warnings: ValidationWarning[]): string {
  const lines = reportLines(report)
  if (includeWarnings) {
    lines.push('', '## Validation Warnings', ...warnings.map((warning) => `- ${warning.field}: ${getExplanation(warning)} Value: ${warning.value}.`))
  }
  return lines.join('\n')
}
