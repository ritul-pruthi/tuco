import type { ReactNode } from 'react'
import { NavLink, useLocation } from 'react-router-dom'

const sections = ['Overview', 'Hosts', 'Connections', 'DNS', 'HTTP', 'TLS', 'Detections', 'Timeline', 'IOCs', 'Evidence']

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
            const path = section === 'Overview' ? '' : `/${section.toLowerCase()}`
            return (
              <NavLink
                className={({ isActive }) => (isActive ? 'nav-item active' : 'nav-item')}
                key={section}
                to={id ? `/investigations/${id}${path}` : '/'}
                end={section === 'Overview'}
              >
                {section}
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
