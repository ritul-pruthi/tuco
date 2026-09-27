import { useEffect, useState } from 'react'

export function App() {
  const [status, setStatus] = useState<'checking...' | 'ok' | 'unreachable'>('checking...')

  useEffect(() => {
    let isMounted = true
    fetch('http://localhost:8000/health')
      .then((res) => {
        if (!res.ok) throw new Error('Network error')
        return res.json()
      })
      .then((data) => {
        if (isMounted) {
          setStatus(data?.status === 'ok' ? 'ok' : 'unreachable')
        }
      })
      .catch(() => {
        if (isMounted) {
          setStatus('unreachable')
        }
      })

    return () => {
      isMounted = false
    }
  }, [])

  return <p>Backend: {status}</p>
}

export default App
