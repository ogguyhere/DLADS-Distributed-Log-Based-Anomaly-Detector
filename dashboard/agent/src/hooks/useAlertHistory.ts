import { useState, useEffect } from 'react'

export interface RatePoint { time: string; count: number }

export function useAlertHistory(alertsFired: number) {
  const [history, setHistory] = useState<RatePoint[]>([])

  useEffect(() => {
    const now = new Date()
    const label = `${now.getHours()}:${String(now.getMinutes()).padStart(2,'0')}:${String(now.getSeconds()).padStart(2,'0')}`
    setHistory(prev => {
      const next = [...prev, { time: label, count: alertsFired }]
      return next.slice(-30) // keep last 30 data points
    })
  }, [alertsFired])

  return history
}