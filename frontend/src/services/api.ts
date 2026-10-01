import type { Detection, DnsRecord, Flow, Host, HttpRecord, Ioc, InvestigationListResponse, InvestigationResponse, TimelineEvent, TlsRecord } from '../types/api'

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

export async function getHosts(id: string): Promise<Host[]> {
  const response = await fetch(`${API_BASE}/investigations/${encodeURIComponent(id)}/hosts`)
  return parseResponse<Host[]>(response)
}

export async function getFlows(id: string): Promise<Flow[]> {
  const response = await fetch(`${API_BASE}/investigations/${encodeURIComponent(id)}/flows`)
  return parseResponse<Flow[]>(response)
}

export async function getDns(id: string): Promise<DnsRecord[]> {
  const response = await fetch(`${API_BASE}/investigations/${encodeURIComponent(id)}/dns`)
  return parseResponse<DnsRecord[]>(response)
}

export async function getHttp(id: string): Promise<HttpRecord[]> {
  const response = await fetch(`${API_BASE}/investigations/${encodeURIComponent(id)}/http`)
  return parseResponse<HttpRecord[]>(response)
}

export async function getTls(id: string): Promise<TlsRecord[]> {
  const response = await fetch(`${API_BASE}/investigations/${encodeURIComponent(id)}/tls`)
  return parseResponse<TlsRecord[]>(response)
}

export async function getDetections(id: string): Promise<Detection[]> {
  const response = await fetch(`${API_BASE}/investigations/${encodeURIComponent(id)}/detections`)
  return parseResponse<Detection[]>(response)
}

export async function getTimeline(id: string): Promise<TimelineEvent[]> {
  const response = await fetch(`${API_BASE}/investigations/${encodeURIComponent(id)}/timeline`)
  return parseResponse<TimelineEvent[]>(response)
}

export async function getIocs(id: string): Promise<Ioc[]> {
  const response = await fetch(`${API_BASE}/investigations/${encodeURIComponent(id)}/iocs`)
  return parseResponse<Ioc[]>(response)
}

export async function getDetection(id: string, detectionId: string): Promise<Detection> {
  const detection = (await getDetections(id)).find((item) => item.id === detectionId)
  if (!detection) throw new Error('Detection not found')
  return detection
}

export async function getFlow(id: string, flowId: string): Promise<Flow> {
  const flow = (await getFlows(id)).find((item) => item.id === flowId)
  if (!flow) throw new Error('Flow not found')
  return flow
}

export async function getHost(id: string, hostId: string): Promise<Host> {
  const host = (await getHosts(id)).find((item) => item.id === hostId)
  if (!host) throw new Error('Host not found')
  return host
}
