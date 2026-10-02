import '@testing-library/jest-dom/vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import Layout from '../src/components/Layout'

describe('Layout', () => {
  it('keeps investigation navigation off the landing page', () => {
    render(<MemoryRouter initialEntries={['/']}><Layout><p>Upload</p></Layout></MemoryRouter>)

    expect(screen.getByText('Upload')).toBeInTheDocument()
    expect(screen.queryByRole('navigation', { name: 'Investigation sections' })).not.toBeInTheDocument()
  })

  it('shows investigation navigation for an open investigation', () => {
    render(<MemoryRouter initialEntries={['/investigations/abc']}><Layout><p>Overview</p></Layout></MemoryRouter>)

    expect(screen.getByRole('navigation', { name: 'Investigation sections' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Hosts' })).toHaveAttribute('href', '/investigations/abc/hosts')
  })
})
