import { useState, useEffect, useCallback } from 'react'

export function useApi<T>(endpoint: string, intervalMs = 2000) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const fetch_ = useCallback(() => {
    fetch(endpoint)
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        return r.json()
      })
      .then(d => {
        // Only update data if we got something back — never replace with empty
        if (Array.isArray(d) && d.length === 0) {
          setLoading(false)
          setError(null)
          return
        }
        setData(d); setError(null); setLoading(false)
      })
      .catch(e => { setError(e.message); setLoading(false) })
  }, [endpoint])

  useEffect(() => {
    fetch_()
    const id = setInterval(fetch_, intervalMs)
    return () => clearInterval(id)
  }, [fetch_, intervalMs])

  return { data, error, loading }
}