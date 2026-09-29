import type { InvestigationListResponse, InvestigationResponse } from '../types/api'

const API_BASE = 'http://localhost:8000/api'

async function parseResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let message = `Request failed (${response.status})`
    try {
      const body = (await response.json()) as { detail?: string }
      if (body.detail) message = body.detail
    } catch {
      // Keep the status-based message when the response is not JSON.
    }
    throw new Error(message)
  }
  return response.json() as Promise<T>
}

export async function listInvestigations(
  limit = 100,
  offset = 0,
): Promise<InvestigationListResponse> {
  const response = await fetch(`${API_BASE}/investigations?limit=${limit}&offset=${offset}`)
  return parseResponse<InvestigationListResponse>(response)
}

export async function uploadInvestigation(file: File): Promise<InvestigationResponse> {
  const formData = new FormData()
  formData.append('file', file)
  const response = await fetch(`${API_BASE}/investigations`, {
    method: 'POST',
    body: formData,
  })
  return parseResponse<InvestigationResponse>(response)
}

export async function getInvestigation(id: string): Promise<InvestigationResponse> {
  const response = await fetch(`${API_BASE}/investigations/${encodeURIComponent(id)}`)
  return parseResponse<InvestigationResponse>(response)
}
