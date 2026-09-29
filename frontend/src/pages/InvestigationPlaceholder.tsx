import { useParams } from 'react-router-dom'

export function InvestigationPlaceholder() {
  const { id, section } = useParams<{ id: string; section?: string }>()
  const label = section ? section.charAt(0).toUpperCase() + section.slice(1) : 'Overview'

  return (
    <section className="placeholder-page">
      <p className="eyebrow">Investigation</p>
      <h1>Investigation {id}</h1>
      <p className="placeholder-section">Section: {label}</p>
      <p className="placeholder-note">Coming in a later sub-task.</p>
    </section>
  )
}

export default InvestigationPlaceholder
