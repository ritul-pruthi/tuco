export interface InvestigationResponse {
  id: string
  filename: string
  format: string
  size_bytes: number
  packet_count: number | null
  started_at: string | null
  ended_at: string | null
  duration_seconds: number | null
  status: string
  created_at: string
}

export interface InvestigationListResponse {
  items: InvestigationResponse[]
  total: number
  limit: number
  offset: number
}

export interface Host {
  id: string
  investigation_id: string
  ip: string
  mac: string | null
  scope: string
  packets_sent: number
  packets_received: number
  bytes_sent: number
  bytes_received: number
  unique_destinations: number
  unique_ports: number
  first_seen: string
  last_seen: string
}

export type Severity = 'low' | 'medium' | 'high' | 'critical'

export interface Detection {
  id: string
  investigation_id: string
  rule_id: string
  title: string
  severity: Severity
  confidence: 'low' | 'medium' | 'high'
  source_ip: string
  source_port: number | null
  destination_ip: string
  destination_port: number | null
  timeframe_start: string
  timeframe_end: string
  observed_metric: string
  observed_value: number
  threshold_description: string
  threshold_value: number
  explanation: string
  evidence: Record<string, unknown>[]
  limitations: string
  created_at: string
}
