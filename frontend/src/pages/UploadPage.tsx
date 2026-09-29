import { useEffect, useState } from 'react'
import type { ChangeEvent, FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { listInvestigations, uploadInvestigation } from '../services/api'
import type { InvestigationResponse } from '../types/api'

function formatSize(bytes: number): string {
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function formatTimestamp(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toISOString().slice(0, 16).replace('T', ' ')
}

export function UploadPage() {
  const navigate = useNavigate()
  const [file, setFile] = useState<File | null>(null)
  const [investigations, setInvestigations] = useState<InvestigationResponse[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [isUploading, setIsUploading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let isMounted = true
    listInvestigations()
      .then((response) => {
        if (isMounted) setInvestigations(Array.isArray(response.items) ? response.items : [])
      })
      .catch((loadError: unknown) => {
        if (isMounted) {
          setError(loadError instanceof Error ? loadError.message : 'Unable to load investigations')
        }
      })
      .finally(() => {
        if (isMounted) setIsLoading(false)
      })

    return () => {
      isMounted = false
    }
  }, [])

  function handleFileChange(event: ChangeEvent<HTMLInputElement>) {
    setFile(event.target.files?.[0] ?? null)
    setError(null)
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!file) {
      setError('Choose a .pcap or .pcapng file first.')
      return
    }

    setIsUploading(true)
    setError(null)
    try {
      const investigation = await uploadInvestigation(file)
      navigate(`/investigations/${investigation.id}`)
    } catch (uploadError: unknown) {
      setError(uploadError instanceof Error ? uploadError.message : 'Upload failed')
    } finally {
      setIsUploading(false)
    }
  }

  return (
    <div className="upload-page">
      <header className="page-header">
        <p className="eyebrow">Evidence intake</p>
        <h1>Upload a capture</h1>
        <p className="page-intro">Start an investigation from a PCAP or PCAPNG capture.</p>
      </header>

      <form className="upload-form" onSubmit={handleSubmit}>
        <label htmlFor="capture-file">Capture file</label>
        <div className="upload-controls">
          <input id="capture-file" type="file" accept=".pcap,.pcapng" onChange={handleFileChange} />
          <button type="submit" disabled={isUploading}>
            {isUploading ? 'Uploading...' : 'Upload capture'}
          </button>
        </div>
        {error && <p className="error-message" role="alert">{error}</p>}
      </form>

      <section className="recent-section" aria-labelledby="recent-heading">
        <div className="section-heading">
          <h2 id="recent-heading">Recent investigations</h2>
          <span className="record-count">{investigations.length} records</span>
        </div>
        {isLoading ? (
          <p className="empty-state">Loading investigations...</p>
        ) : investigations.length === 0 ? (
          <p className="empty-state">No investigations yet. Upload a capture above to begin.</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th scope="col">Filename</th>
                  <th scope="col">Format</th>
                  <th className="numeric" scope="col">Size</th>
                  <th className="numeric" scope="col">Packets</th>
                  <th scope="col">Status</th>
                  <th scope="col">Created</th>
                </tr>
              </thead>
              <tbody>
                {investigations.map((investigation) => (
                  <tr
                    className="investigation-row"
                    key={investigation.id}
                    onClick={() => navigate(`/investigations/${investigation.id}`)}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter' || event.key === ' ') navigate(`/investigations/${investigation.id}`)
                    }}
                    tabIndex={0}
                  >
                    <td className="mono">{investigation.filename}</td>
                    <td className="mono">{investigation.format}</td>
                    <td className="mono numeric">{formatSize(investigation.size_bytes)}</td>
                    <td className="mono numeric">{investigation.packet_count ?? '-'}</td>
                    <td><span className={`status status-${investigation.status}`}>{investigation.status}</span></td>
                    <td>{formatTimestamp(investigation.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}

export default UploadPage
