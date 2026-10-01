import type { ReactNode } from 'react'
import { NavLink, useLocation } from 'react-router-dom'

const sections = [
  { label: 'Overview', path: '' },
  { label: 'Hosts', path: '/hosts' },
  { label: 'Connections', path: '/connections' },
  { label: 'DNS', path: '/dns' },
  { label: 'HTTP', path: '/http' },
  { label: 'TLS', path: '/tls' },
  { label: 'Detections', path: '/detections' },
  { label: 'Timeline', path: '/timeline' },
  { label: 'Observables', path: '/iocs' },
]

interface LayoutProps {
  children: ReactNode
}

export function Layout({ children }: LayoutProps) {
  const { pathname } = useLocation()
  const id = pathname.match(/^\/investigations\/([^/]+)/)?.[1]

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <NavLink className="brand" to="/">TUCO</NavLink>
        <nav aria-label="Investigation sections">
          {sections.map((section) => {
            return (
              <NavLink
                className={({ isActive }) => (isActive ? 'nav-item active' : 'nav-item')}
                key={section.label}
                to={id ? `/investigations/${id}${section.path}` : '/'}
                end={section.label === 'Overview'}
              >
                {section.label}
              </NavLink>
            )
          })}
        </nav>
      </aside>
      <main className="main-content">{children}</main>
    </div>
  )
}

export default Layout
