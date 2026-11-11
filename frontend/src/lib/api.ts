export const API = 'http://localhost:8000'

async function j<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(`${API}${path}`, init)
  if (!r.ok) {
    let msg = String(r.status)
    try { msg += ' ' + JSON.stringify((await r.json()).detail) } catch { /* ignore */ }
    throw new Error(msg)
  }
  return r.json() as Promise<T>
}

const post = (body: unknown): RequestInit => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
})

export const getHealth = () => j<any>('/api/health')
export const getLabs = () => j<string[]>('/api/labs')
export const startScan = (lab: string) => j<{ run_id: string }>('/api/scan', post({ lab }))
export const getRun = (id: string) => j<any>(`/api/runs/${id}`)
export const getBriefing = (id: string) =>
  j<{ script: string; word_count: number; audio_url: string | null }>(`/api/briefing/${id}`)
export const getMetrics = () => j<any>('/api/metrics')
export const setChaos = (rate: number) => j<any>('/api/chaos', post({ cloud_failure_rate: rate }))
export const verifyClaim = (cve_id: string, claim: string) =>
  j<any>('/api/verify', post({ cve_id, claim }))