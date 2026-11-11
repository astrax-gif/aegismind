import { useEffect, useState } from 'react'
import { API } from './api'

export type TraceEvent = { seq: number; [k: string]: any }

export function useRunStream(runId: string | null) {
  const [events, setEvents] = useState<TraceEvent[]>([])
  const [done, setDone] = useState(false)

  useEffect(() => {
    setEvents([])
    setDone(false)
    if (!runId) return
    const es = new EventSource(`${API}/api/runs/${runId}/stream`)
    es.onmessage = (m) => {
      try {
        const ev = JSON.parse(m.data) as TraceEvent
        setEvents((prev) => (prev.some((e) => e.seq === ev.seq) ? prev : [...prev, ev]))
      } catch { /* ignore bad frame */ }
    }
    es.onerror = () => { es.close(); setDone(true) }
    return () => es.close()
  }, [runId])

  return { events, done }
}