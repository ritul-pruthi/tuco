import { render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from '../src/App'

describe('App', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ status: 'ok' }),
      }),
    )
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('renders backend ok status when fetch succeeds', async () => {
    render(<App />)
    expect(await screen.findByText('Backend: ok')).toBeDefined()
  })
})
