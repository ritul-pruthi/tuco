import { Link } from 'react-router-dom'

export function NotFoundPage() {
  return (
    <section className="placeholder-page">
      <h1>404 - Not found</h1>
      <Link className="text-link" to="/">Return to upload</Link>
    </section>
  )
}

export default NotFoundPage
