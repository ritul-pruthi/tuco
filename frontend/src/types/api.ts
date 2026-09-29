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
